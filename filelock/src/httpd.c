/*
 * httpd.c — 内置本地 HTTP 服务 + 图形界面 API
 * 只监听 127.0.0.1，不对外网开放。
 */
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <process.h>
#  include <wincrypt.h>
#else
#  include <time.h>
#  ifndef CLOCK_MONOTONIC
#    include <time.h>
#  endif
#endif
#include <time.h>
#include "filelock.h"
#include "web_embedded.h"   /* 构建时由 tools/embed_web.c 生成 */
#ifndef _WIN32
#  include <pthread.h>
#endif

#ifdef _MSC_VER
#  pragma comment(lib, "advapi32.lib")
#endif

#ifdef _MSC_VER
#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "comdlg32.lib")
#  pragma comment(lib, "shell32.lib")
#  pragma comment(lib, "ole32.lib")
#endif

#ifdef _WIN32
typedef SOCKET sock_t;
#  define CLOSESOCK closesocket
#  define SOCK_ERR SOCKET_ERROR
#  define INVALID_SOCK INVALID_SOCKET
#else
typedef int sock_t;
#  define CLOSESOCK close
#  define SOCK_ERR (-1)
#  define INVALID_SOCK (-1)
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#endif

#define REQ_CAP (256 * 1024)

static const char *mime_of(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (strcmp(dot, ".html") == 0) return "text/html; charset=utf-8";
    if (strcmp(dot, ".js") == 0)   return "application/javascript; charset=utf-8";
    if (strcmp(dot, ".css") == 0)  return "text/css; charset=utf-8";
    if (strcmp(dot, ".svg") == 0)  return "image/svg+xml";
    if (strcmp(dot, ".png") == 0)  return "image/png";
    if (strcmp(dot, ".ico") == 0)  return "image/x-icon";
    return "application/octet-stream";
}

static char *strcasestr_compat(const char *hay, const char *needle);

/* 并发连接上限：每个连接一个线程，超出直接拒绝，避免资源耗尽 */
#define MAX_CONNS 64
static volatile long g_active_conns = 0;
#ifdef _WIN32
static void conn_inc(void) { InterlockedIncrement(&g_active_conns); }
static void conn_done(void) { InterlockedDecrement(&g_active_conns); }
/* volatile long 直接读取即为原子快照，无需函数调用 */
#define conn_count() (g_active_conns)
#else
static void conn_inc(void) { __sync_fetch_and_add(&g_active_conns, 1); }
static void conn_done(void) { __sync_fetch_and_sub(&g_active_conns, 1); }
#define conn_count() (g_active_conns)
#endif

static void send_all(sock_t s, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int n = (int)send(s, buf + sent, (int)(len - sent), 0);
        if (n <= 0) return;
        sent += (size_t)n;
    }
}

static void send_response(sock_t s, int code, const char *ctype, const char *body, size_t blen)
{
    char hdr[512];
    const char *msg = code == 200 ? "OK" :
        (code == 400 ? "Bad Request" :
         (code == 403 ? "Forbidden" :
          (code == 404 ? "Not Found" :
           (code == 405 ? "Method Not Allowed" :
            (code == 413 ? "Payload Too Large" : "Internal Server Error")))));
    /* 安全响应头：
     * - X-Frame-Options DENY：禁止恶意网页把界面嵌进 iframe 诱导点击（clickjacking）；
     * - CSP：脚本/样式仅允许同源与内联，禁 frame/object，进一步压缩 XSS 面。
     * 注：本服务只有 http://127.0.0.1，HSTS 不适用（浏览器会忽略非 https 的
     * HSTS 头），因此不再发送，避免误导。 */
    int hlen = snprintf(hdr, sizeof(hdr),
                        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                        "Connection: close\r\nCache-Control: no-store\r\n"
                        "X-Frame-Options: DENY\r\n"
                        "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'\r\n"
                        "Access-Control-Allow-Origin: *\r\n\r\n",
                        code, msg, ctype, blen);
    send_all(s, hdr, (size_t)hlen);
    if (blen) send_all(s, body, blen);
}

static void send_json(sock_t s, const char *json)
{
    send_response(s, 200, "application/json; charset=utf-8", json, strlen(json));
}

/* ---------- CSRF 会话令牌 ----------
 * 服务只监听 127.0.0.1，但本机上的任意网页仍可向本端口发起请求（DNS rebinding /
 * CSRF），从而在用户不知情时结束进程、删除文件。为此：
 *   1. 启动时生成随机 Token；前端页面加载后先 GET /api/init 取回 Token；
 *   2. 所有危险 API（POST）必须携带 X-Filelock-Token 请求头，否则返回 403；
 *   3. 响应带 Access-Control-Allow-Origin: *，但自定义请求头会触发 CORS 预检，
 *      而服务端不允许该头 → 跨源脚本无法完成危险调用（简单请求则不带 Token → 403）。
 */
#define TOKEN_HEADER "X-Filelock-Token"

static char g_session_token[65] = { 0 };

/* 服务器静态资源根目录（httpd_serve 启动时设置，供历史条目路径校验使用） */
static char g_webroot[4096] = "";


void httpd_init_token(void)
{
    unsigned char buf[32];
    int ok = 0;
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        ok = CryptGenRandom(hProv, 32, buf) ? 1 : 0;
        CryptReleaseContext(hProv, 0);
    }
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { ok = (fread(buf, 1, 32, f) == 32) ? 1 : 0; fclose(f); }
#endif
    if (!ok) {   /* 兜底：时间 + PID 混合播种 */
#ifdef _WIN32
        srand((unsigned)time(NULL) ^ (unsigned)GetCurrentProcessId());
#else
        srand((unsigned)time(NULL) ^ (unsigned)getpid());
#endif
        for (int i = 0; i < 32; i++) buf[i] = (unsigned char)(rand() & 0xFF);
    }
    for (int i = 0; i < 32; i++) sprintf(g_session_token + i * 2, "%02x", buf[i]);
    g_session_token[64] = 0;
}

const char *httpd_get_token(void)
{
    if (!g_session_token[0]) httpd_init_token();
    return g_session_token;
}

/* 恒定时间字符串比较：相等返回 0。防止通过响应时延逐字节猜出令牌 */
static int token_equal(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return 1;
    unsigned char diff = 0;
    for (size_t i = 0; i < la; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff;
}

/* 从原始请求头中提取指定头的值（大小写不敏感），写入 out；找不到返回 0 */
static int get_header(const char *req, const char *name, char *out, size_t n)
{
    size_t nl = strlen(name);
    const char *hdr_end = strstr(req, "\r\n\r\n");
    for (const char *p = req; p && (!hdr_end || p < hdr_end); ) {
        const char *eol = strstr(p, "\r\n");
        const char *line_end = eol ? eol : (hdr_end ? hdr_end : p + strlen(p));
        if ((size_t)(line_end - p) > nl && strncasecmp(p, name, nl) == 0 && p[nl] == ':') {
            const char *v = p + nl + 1;
            while (v < line_end && (*v == ' ' || *v == '\t')) v++;
            size_t len = (size_t)(line_end - v);
            while (len && (v[len - 1] == ' ' || v[len - 1] == '\t')) len--;
            if (len >= n) len = n - 1;
            memcpy(out, v, len);
            out[len] = 0;
            return 1;
        }
        if (!eol) break;
        p = eol + 2;
    }
    return 0;
}

/* DNS Rebinding 第二层防御：校验 Host 头只允许本机回环地址。
 * （令牌已能挡住绝大多数跨源攻击——自定义头会触发 CORS 预检而被拦截；
 *  但若受害者浏览器被恶意域名解析到 127.0.0.1 且页面同源化，Host 白名单
 *  仍能拒绝非本机 Host 的请求。） */
static int host_is_loopback(const char *req)
{
    char host[256] = "";
    if (!get_header(req, "Host", host, sizeof(host))) return 0;   /* 缺失 Host（HTTP/1.0）→ 拒绝 */
    static const char *names[] = { "localhost", "127.0.0.1", "[::1]", "::1" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        size_t nl = strlen(names[i]);
        if (strncmp(host, names[i], nl) == 0 &&
            (host[nl] == 0 || host[nl] == ':')) return 1;
    }
    return 0;
}

static void send_forbidden(sock_t s)
{
    const char *err = "{\"ok\":0,\"error\":\"CSRF 令牌校验失败：请刷新页面重试\"}";
    send_response(s, 403, "application/json; charset=utf-8", err, strlen(err));
}

/* GET /api/init —— 下发会话令牌与版本信息 */
static void api_init(sock_t s)
{
    char out[256];
    snprintf(out, sizeof(out), "{\"ok\":1,\"token\":\"%s\",\"version\":\"1.2\"}",
             httpd_get_token());
    send_json(s, out);
}

static int read_request(sock_t s, char *buf, size_t cap, size_t *out_len)
{
    /* 读取超时：防止恶意/卡死的连接长期占用服务线程（慢速攻击防御） */
#ifdef _WIN32
    DWORD tv = 5000;   /* ms */
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    size_t got = 0;
    size_t hdr_end = 0;
    long content_len = -1;
    for (;;) {
        if (got + 1 >= cap) return -1;
        int n = (int)recv(s, buf + got, (int)(cap - got - 1), 0);
        if (n <= 0) break;
        got += (size_t)n;
        buf[got] = 0;

        if (!hdr_end) {
            char *p = strstr(buf, "\r\n\r\n");
            if (p) {
                hdr_end = (size_t)(p - buf) + 4;
                /* 只在头部区域内查 Content-Length：避免请求体里恰好出现
                 * "Content-Length:" 字样导致跨块读取错误 */
                char saved = *p;
                *p = 0;
                char *cl = strcasestr_compat(buf, "Content-Length:");
                *p = saved;
                if (cl) content_len = strtol(cl + 15, NULL, 10);
                if (content_len < 0) content_len = 0;
                /* 防御：声明的正文超过缓冲区上限 → 直接拒绝（413），不再读取 */
                if (content_len > (long)cap - 1) return 2;
            }
        }
        if (hdr_end && (long)(got - hdr_end) >= content_len) break;
    }
    *out_len = got;
    return 0;
}

/* strcasestr 可移植替代（仅用于请求头，安全） */
static char *strcasestr_compat(const char *hay, const char *needle)
{
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        for (; i < nl; i++) {
            char a = p[i], b = needle[i];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
        }
        if (i == nl) return (char *)p;
    }
    return NULL;
}

/* ---------- API 实现 ---------- */

static void api_scan(sock_t s, const char *body)
{
    char path[4096] = "";
    if (json_get_string(body, "path", path, sizeof(path)) != 0 || !path[0]) {
        send_json(s, "{\"ok\":0,\"error\":\"缺少 path 参数\"}");
        return;
    }
    int deep = json_get_int(body, "deep", 0);
    Report r;
    diagnose_path(path, &r, deep);
    history_add(path, &r);   /* 写入本地历史 */

    char esc[8192], out[65536];
    size_t o = 0;
    o += (size_t)snprintf(out + o, sizeof(out) - o,
        "{\"ok\":1,\"path\":\"%s\",\"exists\":%d,\"isDir\":%d,\"isLink\":%d,"
        "\"canRead\":%d,\"canWrite\":%d,\"canDelete\":%d,\"size\":%lld,",
        (json_escape(path, esc, sizeof(esc)), esc), r.exists, r.is_dir, r.is_link,
        r.can_read, r.can_write, r.can_delete, r.size);

    o += (size_t)snprintf(out + o, sizeof(out) - o, "\"lockers\":[");
    for (int i = 0; i < r.nlockers && o + 1024 < sizeof(out); i++) {
        char n1[256], n2[512];
        json_escape(r.lockers[i].name, n1, sizeof(n1));
        json_escape(r.lockers[i].detail, n2, sizeof(n2));
        o += (size_t)snprintf(out + o, sizeof(out) - o,
            "%s{\"pid\":%ld,\"ppid\":%ld,\"name\":\"%s\",\"detail\":\"%s\"}", i ? "," : "",
            r.lockers[i].pid, r.lockers[i].ppid, n1, n2);
    }
    o += (size_t)snprintf(out + o, sizeof(out) - o, "],\"reasons\":[");
    for (int i = 0; i < r.nreasons && o + 1024 < sizeof(out); i++) {
        json_escape(r.reasons[i], esc, sizeof(esc));
        o += (size_t)snprintf(out + o, sizeof(out) - o, "%s\"%s\"", i ? "," : "", esc);
    }
    o += (size_t)snprintf(out + o, sizeof(out) - o, "],\"fixes\":[");
    for (int i = 0; i < r.nfixes && o + 1024 < sizeof(out); i++) {
        json_escape(r.fixes[i], esc, sizeof(esc));
        o += (size_t)snprintf(out + o, sizeof(out) - o, "%s\"%s\"", i ? "," : "", esc);
    }

    const char *conclusion =
        !r.exists ? "路径不存在或无法访问" :
        (r.nlockers > 0 ? "找到占用进程，关闭它们即可解除占用" :
         (r.restricted ? "找到受限原因，按建议逐条处理" : "该路径当前没有被占用"));
    json_escape(conclusion, esc, sizeof(esc));
    snprintf(out + o, sizeof(out) - o, "],\"conclusion\":\"%s\"}", esc);
    send_json(s, out);
}

static void api_analyze(sock_t s, const char *body)
{
    char text[32768] = "";
    if (json_get_string(body, "text", text, sizeof(text)) != 0 || !text[0]) {
        send_json(s, "{\"ok\":0,\"error\":\"请先粘贴报错提示文本\"}");
        return;
    }
    RuleHit hits[16];
    int n = analyze_text(text, hits, 16);
    char paths[8][ITEM_LEN];
    int np = extract_paths(text, paths, 8);

    char esc[4096], out[65536];
    size_t o = 0;
    o += (size_t)snprintf(out + o, sizeof(out) - o, "{\"ok\":1,\"rules\":[");
    for (int i = 0; i < n && o + 2048 < sizeof(out); i++) {
        json_escape(hits[i].cause, esc, sizeof(esc));
        o += (size_t)snprintf(out + o, sizeof(out) - o,
            "%s{\"cause\":\"%s\",\"platform\":%d,\"hits\":%d,\"fixes\":[",
            i ? "," : "", esc, hits[i].platform, hits[i].hits);
        for (int f = 0; f < hits[i].nfixes; f++) {
            char e2[1024];
            json_escape(hits[i].fixes[f], e2, sizeof(e2));
            o += (size_t)snprintf(out + o, sizeof(out) - o, "%s\"%s\"", f ? "," : "", e2);
        }
        o += (size_t)snprintf(out + o, sizeof(out) - o, "]}");
    }
    o += (size_t)snprintf(out + o, sizeof(out) - o, "],\"paths\":[");
    for (int i = 0; i < np && o + 1024 < sizeof(out); i++) {
        json_escape(paths[i], esc, sizeof(esc));
        o += (size_t)snprintf(out + o, sizeof(out) - o, "%s\"%s\"", i ? "," : "", esc);
    }
    snprintf(out + o, sizeof(out) - o, "]}");
    send_json(s, out);
}

static void api_unlock(sock_t s, const char *body)
{
    char path[4096] = "";
    if (json_get_string(body, "path", path, sizeof(path)) != 0 || !path[0]) {
        send_json(s, "{\"ok\":0,\"error\":\"缺少 path 参数\"}");
        return;
    }
    struct stat st;
    int is_dir = (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) ? 1 : 0;

    UnlockHit hits[32];
    int closed = 0, nhits = 0;
    char err[256] = "";
    int rc = close_file_handles(path, is_dir, &closed, hits, 32, err, sizeof(err));
    (void)nhits;

    char esc[512], out[16384];
    if (rc != 0) {
        json_escape(err, esc, sizeof(esc));
        snprintf(out, sizeof(out), "{\"ok\":0,\"error\":\"%s\",\"closed\":%d}", esc, closed);
    } else {
        size_t o = (size_t)snprintf(out, sizeof(out), "{\"ok\":1,\"closed\":%d,\"processes\":[", closed);
        for (int i = 0; i < 32 && hits[i].pid && o + 300 < sizeof(out); i++) {
            char e2[256];
            json_escape(hits[i].name, e2, sizeof(e2));
            o += (size_t)snprintf(out + o, sizeof(out) - o,
                "%s{\"pid\":%ld,\"name\":\"%s\",\"count\":%d}",
                i ? "," : "", hits[i].pid, e2, hits[i].count);
        }
        snprintf(out + o, sizeof(out) - o, "]}");
    }
    send_json(s, out);
}

static void api_act(sock_t s, const char *body)
{
    char path[4096] = "", op[32] = "";
    if (json_get_string(body, "path", path, sizeof(path)) != 0 || !path[0] ||
        json_get_string(body, "op", op, sizeof(op)) != 0) {
        send_json(s, "{\"ok\":0,\"error\":\"缺少参数\"}");
        return;
    }
    if (strcmp(op, "delete") != 0) {
        send_json(s, "{\"ok\":0,\"error\":\"暂只支持 delete 操作\"}");
        return;
    }
    /* 自我保护：拒绝删除本程序目录下的 web 资源（源码运行模式下
     * webroot 指向仓库内 web/，误删会导致界面丢失） */
    if (g_webroot[0]) {
        size_t wl = strlen(g_webroot);
        if (strncmp(path, g_webroot, wl) == 0 && (path[wl] == '/' || path[wl] == '\\')) {
            send_json(s, "{\"ok\":0,\"error\":\"出于安全考虑，不允许删除 filelock 自身的界面文件\"}");
            return;
        }
    }
    struct stat st;
    int is_dir = (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) ? 1 : 0;
    int rc = is_dir ? rmdir(path) : remove(path);
    if (rc == 0) {
        send_json(s, "{\"ok\":1,\"deleted\":1}");
    } else {
        char e[256], esc[512], out[600];
        snprintf(e, sizeof(e), "%s（%s）", strerror(errno),
                 is_dir ? "目录需为空才能删除" : "文件可能仍被占用或只读");
        json_escape(e, esc, sizeof(esc));
        snprintf(out, sizeof(out), "{\"ok\":0,\"error\":\"%s\"}", esc);
        send_json(s, out);
    }
}

static void api_scan_batch(sock_t s, const char *body)
{
    char paths[24][ITEM_LEN];
    int n = json_array_strings(body, "paths", paths, 24);
    if (n == 0) {
        send_json(s, "{\"ok\":0,\"error\":\"缺少 paths 数组\"}");
        return;
    }
    char out[65536];
    size_t o = (size_t)snprintf(out, sizeof(out), "{\"ok\":1,\"results\":[");
    for (int i = 0; i < n && o + 1200 < sizeof(out); i++) {
        Report r;
        diagnose_path(paths[i], &r, 0);
        history_add(paths[i], &r);
        const char *con = !r.exists ? "路径不存在或无法访问" :
                          (r.nlockers > 0 ? "找到占用进程" :
                           (r.restricted ? "找到受限原因" : "没有被占用"));
        char e1[ITEM_LEN * 2], e2[ITEM_LEN * 2];
        json_escape(paths[i], e1, sizeof(e1));
        json_escape(con, e2, sizeof(e2));
        o += (size_t)snprintf(out + o, sizeof(out) - o,
            "%s{\"path\":\"%s\",\"exists\":%d,\"isDir\":%d,\"canDelete\":%d,"
            "\"nlockers\":%d,\"restricted\":%d,\"conclusion\":\"%s\"}",
            i ? "," : "", e1, r.exists, r.is_dir, r.can_delete,
            r.nlockers, r.restricted, e2);
    }
    snprintf(out + o, sizeof(out) - o, "]}");
    send_json(s, out);
}

static void api_force_clean(sock_t s, const char *body)
{
    char path[4096] = "";
    if (json_get_string(body, "path", path, sizeof(path)) != 0 || !path[0]) {
        send_json(s, "{\"ok\":0,\"error\":\"缺少 path 参数\"}");
        return;
    }
    struct stat st;
    int is_dir = (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) ? 1 : 0;

    /* 自我保护：拒绝删除本程序目录下的 web 资源（与 /api/act 同规则） */
    if (g_webroot[0]) {
        size_t wl = strlen(g_webroot);
        if (strncmp(path, g_webroot, wl) == 0 && (path[wl] == '/' || path[wl] == '\\')) {
            send_json(s, "{\"ok\":0,\"error\":\"出于安全考虑，不允许删除 filelock 自身的界面文件\"}");
            return;
        }
    }

    /* 1) 句柄级解锁（Windows） */
    UnlockHit hits[32];
    int closed = 0;
    char unlock_err[256] = "";
    close_file_handles(path, is_dir, &closed, hits, 32, unlock_err, sizeof(unlock_err));

    /* 2) 删除 */
    int deleted = 0;
    char del_err[256] = "";
    int rc = is_dir ? rmdir(path) : remove(path);
    if (rc == 0) deleted = 1;
    else snprintf(del_err, sizeof(del_err), "%s（%s）", strerror(errno),
                  is_dir ? "目录需为空" : "可能仍被占用或只读");

    /* 3) 复测 */
    Report r;
    diagnose_path(path, &r, 0);
    if (r.exists) history_add(path, &r);

    char esc[512], out[2048];
    json_escape(del_err, esc, sizeof(esc));
    snprintf(out, sizeof(out),
        "{\"ok\":1,\"closed\":%d,\"deleted\":%d,\"deleteError\":\"%s\","
        "\"stillExists\":%d,\"remainLockers\":%d}",
        closed, deleted, deleted ? "" : esc, r.exists, r.nlockers);
    send_json(s, out);
}

static void api_history(sock_t s)
{
    HistoryItem items[20];
    int n = history_list(items, 20);
    /* 防御：若历史文件被外部篡改，path 字段可能指向本程序内嵌的
     * index.html/app.js/style.css——用户点击历史记录会触发删除/解锁，
     * 因此拒绝展示与内嵌 Web 资源同名的条目。 */
    static const char *protected_names[] = { "/index.html", "/app.js", "/style.css" };
    int wlen = (int)strlen(g_webroot);
    for (int i = n - 1; i >= 0; i--) {
        const char *p = items[i].path;
        if (!p[0]) { memmove(&items[i], &items[i + 1], (size_t)(n - 1 - i) * sizeof(HistoryItem)); n--; continue; }
        int bad = 0;
        if (wlen > 0 && strncmp(p, g_webroot, (size_t)wlen) == 0) {
            const char *rest = p + wlen;
            for (size_t k = 0; k < sizeof(protected_names) / sizeof(protected_names[0]); k++)
                if (strcmp(rest, protected_names[k]) == 0) bad = 1;
        }
        if (bad) { memmove(&items[i], &items[i + 1], (size_t)(n - 1 - i) * sizeof(HistoryItem)); n--; }
    }
    char out[48000];
    size_t o = (size_t)snprintf(out, sizeof(out), "{\"ok\":1,\"items\":[");
    for (int i = 0; i < n && o + 2048 < sizeof(out); i++) {
        char e1[ITEM_LEN * 2], e2[ITEM_LEN * 2];
        json_escape(items[i].path, e1, sizeof(e1));
        json_escape(items[i].conclusion, e2, sizeof(e2));
        o += (size_t)snprintf(out + o, sizeof(out) - o,
            "%s{\"path\":\"%s\",\"conclusion\":\"%s\",\"exists\":%d,"
            "\"nlockers\":%d,\"restricted\":%d,\"ts\":%lld}",
            i ? "," : "", e1, e2, items[i].exists, items[i].nlockers,
            items[i].restricted, items[i].ts);
    }
    snprintf(out + o, sizeof(out) - o, "]}");
    send_json(s, out);
}

static void api_history_clear(sock_t s)
{
    int rc = history_clear();
    send_json(s, rc == 0 ? "{\"ok\":1}" : "{\"ok\":0,\"error\":\"清空失败\"}");
}

static void api_browse(sock_t s, const char *body)
{
    char type[16] = "file";
    json_get_string(body, "type", type, sizeof(type));
    char path[4096] = "", err[256] = "";
    if (native_browse(type, path, sizeof(path), err, sizeof(err)) == 0) {
        char esc[8192], out[9000];
        json_escape(path, esc, sizeof(esc));
        snprintf(out, sizeof(out), "{\"ok\":1,\"path\":\"%s\"}", esc);
        send_json(s, out);
    } else {
        char esc[512], out[600];
        json_escape(err, esc, sizeof(esc));
        snprintf(out, sizeof(out), "{\"ok\":0,\"error\":\"%s\"}", esc);
        send_json(s, out);
    }
}

static void api_kill(sock_t s, const char *body)
{
    /* 用 json_get_int 解析（数字与字符串两种写法都支持），并校验纯数字，
     * 避免 atol("9abc")==9 这类宽松解析误杀无关进程 */
    long pid = (long)json_get_int(body, "pid", -1);
    {
        const char *p = strstr(body, "\"pid\"");
        if (!p || pid <= 0) { send_json(s, "{\"ok\":0,\"error\":\"缺少有效 pid\"}"); return; }
        p += 5;
        while (*p == ' ' || *p == ':' || *p == '\t' || *p == '"') p++;
        if (!(*p >= '0' && *p <= '9')) { send_json(s, "{\"ok\":0,\"error\":\"缺少有效 pid\"}"); return; }
    }
    if (pid > 0x7FFFFFFF) { send_json(s, "{\"ok\":0,\"error\":\"缺少有效 pid\"}"); return; }
    /* 自我保护：拒绝结束 filelock 自身（kill_locker 内也有同样防线） */
    long self_pid = 0;
#ifdef _WIN32
    self_pid = (long)GetCurrentProcessId();
#else
    self_pid = (long)getpid();
#endif
    if (pid == self_pid) {
        send_json(s, "{\"ok\":0,\"error\":\"不能结束 filelock 自身的进程\"}");
        return;
    }
    Locker L; memset(&L, 0, sizeof(L)); L.pid = pid;
    int rc = kill_locker(&L);
    char out[128];
    snprintf(out, sizeof(out), "{\"ok\":%d,\"pid\":%ld}", rc == 0 ? 1 : 0, pid);
    send_json(s, out);
}

/* 系统剪贴板内容指纹缓存：前端在聚焦/粘贴时会多次拉取剪贴板，
 * 内容未变且距上次读取不足 2 秒时直接返回空结果，避免频繁 fork pbpaste/xclip。 */
static struct {
    char hash[64];
    long long last_ms;
    int inited;
} g_clip_cache;

static long long now_ms(void)
{
#ifdef _WIN32
    return (long long)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

static void api_clipboard(sock_t s)
{
    static char buf[8192];
    int rc = clipboard_read(buf, sizeof(buf));
    if (rc > 0) {
        /* FNV-1a 快速指纹：内容没变且刚读过 → 返回空，让前端沿用现有值 */
        unsigned long long h = 1469598103934665603ULL;
        for (const char *p = buf; *p; p++) { h ^= (unsigned char)*p; h *= 1099511628211ULL; }
        char hash[32];
        snprintf(hash, sizeof(hash), "%016llx", h);
        long long t = now_ms();
        if (g_clip_cache.inited && strcmp(g_clip_cache.hash, hash) == 0 &&
            t - g_clip_cache.last_ms < 2000) {
            send_json(s, "{\"ok\":1,\"text\":\"\",\"unchanged\":1}");
            return;
        }
        snprintf(g_clip_cache.hash, sizeof(g_clip_cache.hash), "%s", hash);
        g_clip_cache.last_ms = t;
        g_clip_cache.inited = 1;
    }
    if (rc <= 0) {
        send_json(s, rc == 0 ? "{\"ok\":1,\"text\":\"\"}" : "{\"ok\":0,\"error\":\"当前系统不支持读取剪贴板\"}");
        return;
    }
    char esc[16384], out[16800];
    json_escape(buf, esc, sizeof(esc));
    snprintf(out, sizeof(out), "{\"ok\":1,\"text\":\"%s\"}", esc);
    send_json(s, out);
}

static void api_locate(sock_t s, const char *body)
{
    char name[512] = "";
    if (json_get_string(body, "name", name, sizeof(name)) != 0 || !name[0]) {
        send_json(s, "{\"ok\":0,\"error\":\"缺少文件名\"}");
        return;
    }
    char paths[8][ITEM_LEN];
    int n = locate_path(name, paths, 8);

    char esc[1024], out[9000];
    size_t o = (size_t)snprintf(out, sizeof(out), "{\"ok\":1,\"paths\":[");
    for (int i = 0; i < n && o + 1100 < sizeof(out); i++) {
        json_escape(paths[i], esc, sizeof(esc));
        o += (size_t)snprintf(out + o, sizeof(out) - o, "%s\"%s\"", i ? "," : "", esc);
    }
    snprintf(out + o, sizeof(out) - o, "]}");
    send_json(s, out);
}

/* 内嵌界面资源（找不到 web 目录时兜底，支持单文件分发） */
typedef struct {
    const char *name;
    const unsigned char *data;
    unsigned int len;
    const char *mime;
} EmbeddedFile;

/* 内嵌 favicon：SVG 放大镜图标，避免浏览器默认请求 /favicon.ico 产生 404 */
static const char EMB_FAVICON_SVG[] =
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>"
    "<circle cx='27' cy='27' r='16' fill='none' stroke='#4f46e5' stroke-width='7'/>"
    "<line x1='39' y1='39' x2='56' y2='56' stroke='#4f46e5' stroke-width='9' stroke-linecap='round'/>"
    "</svg>";

static const EmbeddedFile EMB_FILES[] = {
    { "/index.html", EMB_INDEX_HTML, EMB_INDEX_HTML_LEN, "text/html; charset=utf-8" },
    { "/app.js",     EMB_APP_JS,     EMB_APP_JS_LEN,     "application/javascript; charset=utf-8" },
    { "/style.css",  EMB_STYLE_CSS,  EMB_STYLE_CSS_LEN,  "text/css; charset=utf-8" },
};

static int send_embedded(sock_t s, const char *url)
{
    const char *name = strcmp(url, "/") == 0 ? "/index.html" : url;
    for (size_t i = 0; i < sizeof(EMB_FILES) / sizeof(EMB_FILES[0]); i++) {
        if (strcmp(name, EMB_FILES[i].name) == 0) {
            send_response(s, 200, EMB_FILES[i].mime,
                          (const char *)EMB_FILES[i].data, EMB_FILES[i].len);
            return 1;
        }
    }
    return 0;
}

static void serve_static(sock_t s, const char *webroot, const char *url)
{
    const char *name = url;
    if (strcmp(url, "/") == 0) name = "/index.html";
    if (strstr(name, "..")) { send_response(s, 400, "text/plain", "bad path", 9); return; }

    char fp[4096];
    snprintf(fp, sizeof(fp), "%s%s", webroot, name);
    FILE *f = fopen(fp, "rb");
    if (!f) {
        /* 回退到内嵌界面（单文件分发模式） */
        if (send_embedded(s, url)) return;
        send_response(s, 404, "text/plain; charset=utf-8", "404 未找到（请检查 web 目录是否存在）", 45);
        return;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len < 0) len = 0;
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) { fclose(f); send_response(s, 500, "text/plain", "oom", 3); return; }
    size_t got = fread(buf, 1, (size_t)len, f);
    fclose(f);
    send_response(s, 200, mime_of(fp), buf, got);
    free(buf);
}

static void handle_conn(sock_t s, const char *webroot)
{
    char *buf = (char *)malloc(REQ_CAP);
    if (!buf) return;
    size_t len = 0;
    int rrc = read_request(s, buf, REQ_CAP, &len);
    if (rrc == 2) {   /* 正文超过上限 → 413 */
        const char *err = "{\"ok\":0,\"error\":\"请求体过大\"}";
        send_response(s, 413, "application/json; charset=utf-8", err, strlen(err));
        free(buf);
        return;
    }
    if (rrc != 0) { free(buf); return; }

    char method[8] = "", url[1024] = "";
    sscanf(buf, "%7s %1023s", method, url);
    char *body = strstr(buf, "\r\n\r\n");
    body = body ? body + 4 : buf + len;

    /* DNS Rebinding 防御：拒绝 Host 非本机回环地址的请求 */
    if (!host_is_loopback(buf)) {
        send_response(s, 403, "text/plain; charset=utf-8",
                      "403 Forbidden (Host)", 21);
        free(buf);
        return;
    }

    /* CORS 预检：仅允许来自本机源的带令牌请求 */
    if (strcmp(method, "OPTIONS") == 0) {
        char origin[256] = "";
        get_header(buf, "Origin", origin, sizeof(origin));
        int allowed = (origin[0] == 0) ||
                      strncmp(origin, "http://localhost", 16) == 0 ||
                      strncmp(origin, "http://127.0.0.1", 16) == 0 ||
                      strncmp(origin, "http://[::1]", 12) == 0;
        char hdr[512];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 204 No Response\r\nVary: Origin\r\n"
            "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, %s\r\n"
            "Access-Control-Max-Age: 600\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            TOKEN_HEADER);
        if (!allowed) { hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); }
        send_all(s, hdr, (size_t)hlen);
        free(buf);
        return;
    }

    if (strcmp(method, "GET") == 0) {
        /* 去掉查询串再路由，兼容 /api/xxx?v=1 之类的写法 */
        char *q = strchr(url, '?');
        if (q) *q = 0;
        if (strcmp(url, "/favicon.ico") == 0) {
            send_response(s, 200, "image/svg+xml", EMB_FAVICON_SVG, sizeof(EMB_FAVICON_SVG) - 1);
        } else if (strcmp(url, "/api/init") == 0) api_init(s);
        else if (strcmp(url, "/api/clipboard") == 0) api_clipboard(s);
        else if (strcmp(url, "/api/history") == 0) api_history(s);
        else serve_static(s, webroot, url);
    } else if (strcmp(method, "POST") == 0) {
        char *q = strchr(url, '?');
        if (q) *q = 0;
        /* CSRF 防护：所有 /api/ 危险操作必须携带有效会话令牌（恒定时间比较） */
        if (strncmp(url, "/api/", 5) == 0) {
            char tok[128] = "";
            if (!get_header(buf, TOKEN_HEADER, tok, sizeof(tok)) ||
                token_equal(tok, httpd_get_token()) != 0) {
                send_forbidden(s);
                free(buf);
                return;
            }
        }
        if (strcmp(url, "/api/scan") == 0) api_scan(s, body);
        else if (strcmp(url, "/api/scan-batch") == 0) api_scan_batch(s, body);
        else if (strcmp(url, "/api/force-clean") == 0) api_force_clean(s, body);
        else if (strcmp(url, "/api/analyze") == 0) api_analyze(s, body);
        else if (strcmp(url, "/api/browse") == 0) api_browse(s, body);
        else if (strcmp(url, "/api/kill") == 0) api_kill(s, body);
        else if (strcmp(url, "/api/locate") == 0) api_locate(s, body);
        else if (strcmp(url, "/api/unlock") == 0) api_unlock(s, body);
        else if (strcmp(url, "/api/act") == 0) api_act(s, body);
        else if (strcmp(url, "/api/history") == 0) api_history(s);      /* GET/POST 均支持 */
        else if (strcmp(url, "/api/history/clear") == 0) api_history_clear(s);
        else send_response(s, 404, "application/json", "{\"ok\":0,\"error\":\"未知接口\"}", 30);
    } else {
        send_response(s, 405, "text/plain", "method not allowed", 18);
    }
    free(buf);
}

/* 每个连接由独立线程处理：原生文件对话框等耗时操作不再阻塞服务 */
typedef struct {
    sock_t s;
    char webroot[4096];
} ConnArg;

#ifdef _WIN32
static DWORD WINAPI conn_thread(LPVOID p)
#else
static void *conn_thread(void *p)
#endif
{
    ConnArg *a = (ConnArg *)p;
    handle_conn(a->s, a->webroot);
    CLOSESOCK(a->s);
    conn_done();
    free(a);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

int httpd_serve(const char *webroot, int *port, void (*on_ready)(int port))
{
    httpd_init_token();   /* CSRF 会话令牌：每次启动随机生成 */
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
#endif

    sock_t srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCK) return -1;

    int on = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int bound = 0;
    for (int p = *port; p < *port + 20; p++) {
        addr.sin_port = htons((unsigned short)p);
        if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            *port = p;
            bound = 1;
            break;
        }
    }
    if (!bound) { CLOSESOCK(srv); return -1; }
    if (listen(srv, 8) == SOCK_ERR) { CLOSESOCK(srv); return -1; }

    snprintf(g_webroot, sizeof(g_webroot), "%s", webroot ? webroot : "");
    if (on_ready) on_ready(*port);

    for (;;) {
        struct sockaddr_in cli;
        socklen_t cl = sizeof(cli);
        sock_t c = accept(srv, (struct sockaddr *)&cli, &cl);
        if (c == INVALID_SOCK) continue;

        /* 并发上限：超出直接拒绝，避免线程/内存被刷爆 */
        if (conn_count() >= MAX_CONNS) { CLOSESOCK(c); continue; }

        ConnArg *a = (ConnArg *)malloc(sizeof(ConnArg));
        if (!a) { conn_inc(); handle_conn(c, webroot); conn_done(); CLOSESOCK(c); continue; }
        a->s = c;
        snprintf(a->webroot, sizeof(a->webroot), "%s", webroot);
        conn_inc();   /* 计数在派发前增加；线程结束时由 conn_done 归还 */

#ifdef _WIN32
        HANDLE th = CreateThread(NULL, 0, conn_thread, a, 0, NULL);
        if (th) CloseHandle(th);
        else { handle_conn(c, webroot); conn_done(); CLOSESOCK(c); free(a); }
#else
        pthread_t th;
        if (pthread_create(&th, NULL, conn_thread, a) == 0) pthread_detach(th);
        else { handle_conn(c, webroot); conn_done(); CLOSESOCK(c); free(a); }
#endif
    }
    return 0;
}

void httpd_open_browser(int port)
{
    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/", port);
#ifdef _WIN32
    ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
#elif defined(__APPLE__)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "open '%s' >/dev/null 2>&1 &", url);
    int rc = system(cmd);
    (void)rc;
#else
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "xdg-open '%s' >/dev/null 2>&1 &", url);
    int rc = system(cmd);
    (void)rc;
#endif
}
