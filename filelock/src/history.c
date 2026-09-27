/*
 * history.c — 检测历史记录（本地留档，JSON Lines 格式）
 * 存储位置：
 *   Windows: %APPDATA%\filelock_history.jsonl
 *   其他    : $HOME/.filelock_history.jsonl
 */
#include "filelock.h"
#include <time.h>

#ifdef _WIN32
#  include <process.h>
#else
#  include <pthread.h>
#endif

#define HISTORY_FILE_MAX 200   /* 超过则截断保留最近 150 条 */

/* 简单互斥锁，避免并发写坏文件 */
#ifdef _WIN32
static CRITICAL_SECTION g_hist_lock;
static int g_hist_init = 0;
static void hist_lock(void)
{
    if (!g_hist_init) { InitializeCriticalSection(&g_hist_lock); g_hist_init = 1; }
    EnterCriticalSection(&g_hist_lock);
}
static void hist_unlock(void) { LeaveCriticalSection(&g_hist_lock); }
#else
static pthread_mutex_t g_hist_lock = PTHREAD_MUTEX_INITIALIZER;
static void hist_lock(void) { pthread_mutex_lock(&g_hist_lock); }
static void hist_unlock(void) { pthread_mutex_unlock(&g_hist_lock); }
#endif

static void history_file(char *out, size_t n)
{
#ifdef _WIN32
    char appdata[1024] = "";
    DWORD len = GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));
    if (len == 0 || len >= sizeof(appdata)) snprintf(appdata, sizeof(appdata), ".");
    snprintf(out, n, "%s\\filelock_history.jsonl", appdata);
#else
    const char *home = getenv("HOME");
    snprintf(out, n, "%s/.filelock_history.jsonl", home && home[0] ? home : ".");
#endif
}

int history_add(const char *path, const Report *r)
{
    char hf[2048], esc_path[ITEM_LEN * 2], esc_con[ITEM_LEN * 2];
    history_file(hf, sizeof(hf));
    json_escape(path, esc_path, sizeof(esc_path));
    json_escape(!r->exists ? "路径不存在或无法访问" :
                (r->nlockers > 0 ? "找到占用进程" :
                 (r->restricted ? "找到受限原因" : "没有被占用")), esc_con, sizeof(esc_con));

    hist_lock();
    FILE *f = fopen(hf, "a");
    if (!f) { hist_unlock(); return -1; }
    fprintf(f, "{\"path\":\"%s\",\"conclusion\":\"%s\",\"exists\":%d,\"nlockers\":%d,"
               "\"restricted\":%d,\"ts\":%ld}\n",
            esc_path, esc_con, r->exists, r->nlockers, r->restricted, (long)time(NULL));
    fclose(f);

    /* 超量截断：文件按时间正序追加，因此应丢弃最旧的行、保留最近的行。
     * （旧实现的 head+skip 写法恰好相反，会把最新记录删掉——已修正为
     *   环形缓冲：始终只记住最后 KEEP_TAIL 条，写回时天然保序。） */
    FILE *rf = fopen(hf, "r");
    if (rf) {
        #define KEEP_TAIL (HISTORY_FILE_MAX - 50)
        static char ring[KEEP_TAIL][2048];   /* 静态分配，避免栈溢出 */
        int lines = 0, w = 0;
        char buf[2048];
        while (fgets(buf, sizeof(buf), rf)) {
            if (buf[strcspn(buf, "\n")] || strlen(buf) >= sizeof(buf) - 1) continue; /* 跳过异常超长行 */
            memcpy(ring[w], buf, strlen(buf) + 1);
            w = (w + 1) % KEEP_TAIL;
            lines++;
        }
        fclose(rf);
        if (lines > HISTORY_FILE_MAX) {
            FILE *wf = fopen(hf, "w");
            if (wf) {
                for (int k = 0; k < KEEP_TAIL; k++) {
                    int idx = (w + k) % KEEP_TAIL;   /* 从最旧的保留行开始输出 */
                    if (ring[idx][0]) fputs(ring[idx], wf);
                }
                fclose(wf);
            }
        }
    }
    hist_unlock();
    return 0;
}

int history_list(HistoryItem *out, int max)
{
    return history_page(out, max, 0, max > 0 ? max : 20, NULL);
}

/* 分页读取：page 从 0 开始，每页 per_page 条（新→旧）。
 * out_cap 为调用方数组容量。返回本页实际条数，*total_out 输出过滤前总条数。 */
int history_page(HistoryItem *out, int out_cap, int page, int per_page, long long *total_out)
{
    if (per_page < 1) per_page = 20;
    if (per_page > 100) per_page = 100;   /* 单页上限，防御超大请求 */
    if (page < 0) page = 0;
    if (out_cap < 0) out_cap = 0;
    char hf[2048];
    history_file(hf, sizeof(hf));
    hist_lock();
    FILE *f = fopen(hf, "r");
    if (!f) {
        hist_unlock();
        if (total_out) *total_out = 0;
        return 0;
    }

    /* 先全部读入行，再倒序（最新的在前）取对应页区间 */
    int cap = 256, n = 0;
    char **lines = (char **)calloc((size_t)cap, sizeof(char *));
    char buf[2048];
    while (fgets(buf, sizeof(buf), f)) {
        if (n >= HISTORY_FILE_MAX + 50) break;   /* 文件理论上已被截断，双保险 */
        if (n == cap) {
            char **nl = (char **)realloc(lines, (size_t)cap * 2 * sizeof(char *));
            if (!nl) break;
            lines = nl;
            memset(lines + cap, 0, (size_t)cap * sizeof(char *));
            cap *= 2;
        }
        lines[n] = (char *)malloc(strlen(buf) + 1);
        if (lines[n]) strcpy(lines[n], buf);
        n++;
    }
    fclose(f);
    hist_unlock();

    if (total_out) *total_out = n;

    long long start = (long long)page * per_page;      /* 本页起始（倒序偏移） */
    long long stop  = start + per_page;                /* 不含 */
    int count = 0;
    for (long long i = start; i < stop && i < n; i++) {
        int idx = n - 1 - (int)i;                      /* 倒序映射到正序行号 */
        if (idx < 0 || !lines[idx]) continue;
        HistoryItem *h = &out[count];
        memset(h, 0, sizeof(*h));
        json_get_string(lines[idx], "path", h->path, sizeof(h->path));
        json_get_string(lines[idx], "conclusion", h->conclusion, sizeof(h->conclusion));
        h->exists = atoi(strstr(lines[idx], "\"exists\":") ? strstr(lines[idx], "\"exists\":") + 9 : "0");
        char *p;
        p = strstr(lines[idx], "\"nlockers\":");  h->nlockers = p ? atoi(p + 11) : 0;
        p = strstr(lines[idx], "\"restricted\":"); h->restricted = p ? atoi(p + 12) : 0;
        p = strstr(lines[idx], "\"ts\":");         h->ts = p ? (long long)atol(p + 5) : 0;
        if (h->path[0] && count < out_cap) count++;
    }
    for (int i = 0; i < n; i++) free(lines[i]);
    free(lines);
    return count;
}

int history_clear(void)
{
    char hf[2048];
    history_file(hf, sizeof(hf));
    hist_lock();
    int rc = remove(hf);
    hist_unlock();
    return rc == 0 ? 0 : -1;
}
