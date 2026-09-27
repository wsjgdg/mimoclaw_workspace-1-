/*
 * diagnose.c — 路径占用诊断引擎（Windows / macOS / Linux）
 */
#include "filelock.h"
#ifndef _WIN32
#  include <pwd.h>
#endif

/* ---------------- 通用工具 ---------------- */

void report_add_reason(Report *r, const char *fmt, ...)
{
    if (r->nreasons >= MAX_ITEMS) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->reasons[r->nreasons], ITEM_LEN, fmt, ap);
    va_end(ap);
    r->nreasons++;
}

void report_add_fix(Report *r, const char *fmt, ...)
{
    if (r->nfixes >= MAX_ITEMS) return;
    char buf[ITEM_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    for (int i = 0; i < r->nfixes; i++)
        if (strcmp(r->fixes[i], buf) == 0) return;
    snprintf(r->fixes[r->nfixes++], ITEM_LEN, "%s", buf);
}

static void shell_quote(const char *in, char *out, size_t n)
{
    size_t o = 0;
    if (o + 1 < n) out[o++] = '\'';
    for (const char *p = in; *p && o + 4 < n; p++) {
        if (*p == '\'') { out[o++] = '\''; out[o++] = '\\'; out[o++] = '\''; out[o++] = '\''; }
        else out[o++] = *p;
    }
    if (o + 2 < n) { out[o++] = '\''; out[o++] = 0; }
    else out[n - 1] = 0;
}

UNUSED_FN static const char *base_name(const char *path)
{
    const char *p = path;
    for (const char *s = path; *s; s++)
        if (*s == '/' || *s == '\\') p = s + 1;
    return p;
}

static void dir_name(const char *path, char *out, size_t n)
{
    size_t len = strlen(path);
    snprintf(out, n, "%s", path);
    while (len > 0 && out[len - 1] != '/' && out[len - 1] != '\\') out[--len] = 0;
    if (len == 0) snprintf(out, n, ".");
    else if (len > 1) out[len - 1] = 0;
}

static long long human_size(long long b, char *unit, size_t un)
{
    if (b >= 1024LL * 1024 * 1024) { snprintf(unit, un, "GB"); return b / (1024LL * 1024 * 1024); }
    if (b >= 1024LL * 1024)        { snprintf(unit, un, "MB"); return b / (1024LL * 1024); }
    if (b >= 1024LL)               { snprintf(unit, un, "KB"); return b / 1024; }
    snprintf(unit, un, "B");
    return b;
}

/* ================= Windows ================= */
#ifdef _WIN32

static void utf8_from_wide(const WCHAR *w, char *out, size_t n)
{
    int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (need <= 0) { snprintf(out, n, "(无法转换)"); return; }
    char *tmp = (char *)malloc((size_t)need);
    if (!tmp) { snprintf(out, n, "(内存不足)"); return; }
    WideCharToMultiByte(CP_UTF8, 0, w, -1, tmp, need, NULL, NULL);
    snprintf(out, n, "%s", tmp);
    free(tmp);
}

static void win_err_text(DWORD e, char *out, size_t n)
{
    switch (e) {
    case ERROR_SHARING_VIOLATION:  snprintf(out, n, "共享冲突（文件正被其他进程打开占用）"); break;
    case ERROR_LOCK_VIOLATION:     snprintf(out, n, "字节区域被其他进程锁定（数据库/下载工具等）"); break;
    case ERROR_USER_MAPPED_FILE:   snprintf(out, n, "文件被映射进某进程内存（内存映射占用）"); break;
    case ERROR_ACCESS_DENIED:      snprintf(out, n, "拒绝访问（权限不足/只读属性/系统保护/安全软件）"); break;
    case ERROR_DELETE_PENDING:     snprintf(out, n, "文件正在删除中（等待最后一个句柄关闭）"); break;
    case ERROR_CURRENT_DIRECTORY:  snprintf(out, n, "该目录是某个进程的当前工作目录"); break;
    case ERROR_DIR_NOT_EMPTY:      snprintf(out, n, "目录非空"); break;
    case ERROR_FILE_NOT_FOUND:     snprintf(out, n, "文件不存在"); break;
    case ERROR_PATH_NOT_FOUND:     snprintf(out, n, "路径不存在"); break;
    case ERROR_INVALID_NAME:       snprintf(out, n, "路径/文件名非法"); break;
    case ERROR_FILENAME_EXCED_RANGE: snprintf(out, n, "路径超过 MAX_PATH(260) 限制"); break;
    case ERROR_WRITE_PROTECT:      snprintf(out, n, "介质被写保护"); break;
    case ERROR_NOT_READY:          snprintf(out, n, "驱动器未就绪"); break;
    case ERROR_BUSY:               snprintf(out, n, "资源忙"); break;
    default: {
        LPWSTR lpMsg = NULL;
        DWORD n2 = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                  FORMAT_MESSAGE_IGNORE_INSERTS, NULL, e, 0, (LPWSTR)&lpMsg, 0, NULL);
        if (n2 && lpMsg) {
            char tmp[256];
            utf8_from_wide(lpMsg, tmp, sizeof(tmp));
            size_t l = strlen(tmp);
            while (l && (tmp[l-1] == '\r' || tmp[l-1] == '\n')) tmp[--l] = 0;
            snprintf(out, n, "%s", tmp);
            LocalFree(lpMsg);
        } else snprintf(out, n, "未知错误");
        break;
    }
    }
}

/* 进程所属账户（Windows: 令牌账户；POSIX: /proc 或 lsof 用户字段） */
#ifdef _WIN32
static void win_proc_user(HANDLE hproc, char *out, size_t n)
{
    out[0] = 0;
    HANDLE tok = NULL;
    if (!OpenProcessToken(hproc, TOKEN_QUERY, &tok)) return;
    DWORD need = 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &need);
    TOKEN_USER *tu = (TOKEN_USER *)malloc(need);
    if (tu && GetTokenInformation(tok, TokenUser, tu, need, &need)) {
        char user[256] = "", domain[256] = "";
        DWORD ulen = sizeof(user), dlen = sizeof(domain);
        SID_NAME_USE use;
        if (LookupAccountSidA(NULL, tu->User.Sid, user, &ulen, domain, &dlen, &use))
            snprintf(out, n, "%s\\%s", domain, user);
    }
    free(tu);
    CloseHandle(tok);
}
#endif

static DWORD try_open(const WCHAR *wpath, DWORD access, DWORD share, int dir)
{
    DWORD flags = dir ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL;
    HANDLE h = CreateFileW(wpath, access, share, NULL, OPEN_EXISTING, flags, NULL);
    if (h == INVALID_HANDLE_VALUE) return GetLastError();
    CloseHandle(h);
    return 0;
}

static void win_to_wide(const char *path, WCHAR *wpath, int cap)
{
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, cap))
        MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, cap);
}

static int win_find_lockers(const WCHAR *wpath, Locker *out, int max)
{
    DWORD sess = 0;
    WCHAR key[CCH_RM_SESSION_KEY + 1] = { 0 };
    if (RmStartSession(&sess, 0, key) != ERROR_SUCCESS) return -1;

    const WCHAR *pw = wpath;
    if (RmRegisterResources(sess, 1, &pw, 0, NULL, 0, NULL) != ERROR_SUCCESS) {
        RmEndSession(sess);
        return -1;
    }

    UINT needed = 0, got = 0;
    DWORD reason = 0;
    RM_PROCESS_INFO *info = NULL;
    DWORD res = RmGetList(sess, &needed, &got, NULL, &reason);
    if (res == ERROR_MORE_DATA && needed > 0) {
        info = (RM_PROCESS_INFO *)calloc(needed, sizeof(RM_PROCESS_INFO));
        if (info) {
            got = needed;
            res = RmGetList(sess, &needed, &got, info, &reason);
            if (res != ERROR_SUCCESS) { free(info); info = NULL; got = 0; }
        }
    } else got = 0;

    int count = 0;
    for (UINT i = 0; i < got && count < max; i++) {
        Locker *L = &out[count];
        L->pid = (long)info[i].Process.dwProcessId;
        utf8_from_wide(info[i].strAppName, L->name, sizeof(L->name));
        char extra[128] = "";
        switch (info[i].ApplicationType) {
        case RmCritical:    snprintf(extra, sizeof(extra), "关键系统进程（不可安全终止）"); break;
        case RmService:     snprintf(extra, sizeof(extra), "Windows 服务"); break;
        case RmExplorer:    snprintf(extra, sizeof(extra), "资源管理器"); break;
        case RmConsole:     snprintf(extra, sizeof(extra), "控制台程序"); break;
        case RmMainWindow:
        case RmOtherWindow: snprintf(extra, sizeof(extra), "图形界面程序"); break;
        default: break;
        }
        HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info[i].Process.dwProcessId);
        if (hp) {
            WCHAR wexe[MAX_PATH * 2] = { 0 };
            DWORD sz = MAX_PATH * 2;
            char user[256] = "";
            win_proc_user(hp, user, sizeof(user));
            if (QueryFullProcessImageNameW(hp, 0, wexe, &sz)) {
                char exe[MAX_PATH * 2];
                utf8_from_wide(wexe, exe, sizeof(exe));
                snprintf(L->detail, sizeof(L->detail), "%s%s%s%s%s", exe,
                         user[0] ? " | 用户 " : "", user,
                         extra[0] ? " | " : "", extra);
            } else snprintf(L->detail, sizeof(L->detail), "%s%s%s",
                            user[0] ? "用户 " : "", user, extra);
            CloseHandle(hp);
        } else snprintf(L->detail, sizeof(L->detail), "%s", extra);
        count++;
    }
    free(info);
    RmEndSession(sess);
    return count;
}

int kill_locker(const Locker *L)
{
    HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)L->pid);
    if (!hp) return -1;
    int ok = TerminateProcess(hp, 1) ? 0 : -1;
    CloseHandle(hp);
    return ok;
}

static int diag_windows(const char *path, Report *r, int deep)
{
    WCHAR wpath[32768];
    win_to_wide(path, wpath, 32768);

    DWORD attr = GetFileAttributesW(wpath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD e = GetLastError();
        char t[256]; win_err_text(e, t, sizeof(t));
        report_add_reason(r, "路径不存在或无法访问：%s（错误 %lu）", t, (unsigned long)e);
        report_add_fix(r, "确认路径拼写；若是网络盘/移动盘，检查设备是否已连接");
        return 2;
    }
    r->exists = 1;
    r->is_dir = (attr & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
    r->is_link = (attr & FILE_ATTRIBUTE_REPARSE_POINT) ? 1 : 0;

    if (attr & FILE_ATTRIBUTE_READONLY) {
        r->restricted = 1;
        report_add_reason(r, "文件带“只读”属性");
        report_add_fix(r, "取消只读属性：attrib -R \"%s\"", path);
    }
    if (attr & FILE_ATTRIBUTE_SYSTEM)
        report_add_reason(r, "文件带“系统”属性，Windows 对其有额外保护");
    if (attr & FILE_ATTRIBUTE_OFFLINE) {
        report_add_reason(r, "文件处于“脱机”状态（内容不在本地磁盘上）");
        report_add_fix(r, "右键 → 属性 → 取消“脱机”/“压缩内容以节省磁盘空间”");
    }
    if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
        report_add_reason(r, "这是链接/联接点，操作会作用到目标上");
        report_add_fix(r, "确认真实目标位置（PowerShell: Get-Item \"%s\" | Select LinkType,Target）", path);
    }
    if (attr & FILE_ATTRIBUTE_ENCRYPTED)
        report_add_reason(r, "文件使用 EFS 加密，换账号访问会被拒绝");

    DWORD shareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    DWORD e;

    e = try_open(wpath, GENERIC_READ, shareAll, r->is_dir);
    if (e == 0) r->can_read = 1;
    else {
        char t[256]; win_err_text(e, t, sizeof(t));
        report_add_reason(r, "无法读取：%s（错误 %lu）", t, (unsigned long)e);
    }

    if (!r->is_dir) {
        e = try_open(wpath, GENERIC_WRITE, shareAll, 0);
        if (e == 0) r->can_write = 1;
        else {
            char t[256]; win_err_text(e, t, sizeof(t));
            report_add_reason(r, "无法写入：%s（错误 %lu）", t, (unsigned long)e);
            r->restricted = 1;
            if (e == ERROR_USER_MAPPED_FILE) {
                report_add_reason(r, "典型场景：程序正在加载该 DLL/数据文件，或页面文件占用");
                report_add_fix(r, "结束相关程序后重试；若是 .dll/.exe，重启后再操作");
            }
            if (e == ERROR_ACCESS_DENIED)
                report_add_fix(r, "右键 → 属性 → 安全 → 检查账号写入权限；或以管理员身份运行");
        }
    }

    e = try_open(wpath, DELETE, shareAll, r->is_dir);
    if (e == 0) r->can_delete = 1;
    else {
        char t[256]; win_err_text(e, t, sizeof(t));
        report_add_reason(r, "无法删除/重命名：%s（错误 %lu）", t, (unsigned long)e);
        r->restricted = 1;
        switch (e) {
        case ERROR_CURRENT_DIRECTORY:
            report_add_fix(r, "该目录是某进程的工作目录：关闭对应程序或让它切换到别的目录（资源管理器最常见）");
            break;
        case ERROR_SHARING_VIOLATION:
        case ERROR_LOCK_VIOLATION:
            report_add_fix(r, "关闭正在使用它的程序（见占用进程列表）后重试");
            break;
        case ERROR_ACCESS_DENIED:
            report_add_fix(r, "以管理员身份运行命令提示符/PowerShell 再操作");
            report_add_fix(r, "检查安全软件（杀毒/EDR/DLP）是否正在扫描或锁定该文件");
            break;
        case ERROR_DELETE_PENDING:
            report_add_fix(r, "稍等片刻；重启后该文件会自动消失");
            break;
        }
    }

    int n = win_find_lockers(wpath, r->lockers, MAX_LOCKERS);
    if (n > 0) {
        r->nlockers = n;
        r->restricted = 1;
        for (int i = 0; i < n; i++)
            report_add_reason(r, "被进程占用：%s (PID %ld)",
                              r->lockers[i].name[0] ? r->lockers[i].name : "(未知)", r->lockers[i].pid);
        report_add_fix(r, "关闭占用进程后再操作；本工具命令行模式可用  filelock -k \"%s\"  强制结束", path);
    } else if (n == 0) {
        if (r->restricted)
            report_add_reason(r, "未发现普通进程句柄，可能是：内核驱动、杀毒软件、Windows Search 索引器或资源管理器预览窗格");
        report_add_fix(r, "关闭资源管理器预览窗格（查看 → 预览窗格），等索引/扫描结束后重试");
    } else {
        report_add_fix(r, "占用进程扫描失败（权限不足？请以管理员身份运行）");
    }

    if (deep && r->is_dir)
        report_add_fix(r, "Windows 目录递归扫描：可对目录内单个文件逐个检测，或用 Process Explorer 的 Handle 搜索");

    if (!r->can_delete && r->is_dir)
        report_add_fix(r, "目录删除失败常见原因：① 某程序以其为工作目录 ② 目录内有文件被打开 ③ 路径过长 ④ 资源管理器正在预览");
    if (r->restricted)
        report_add_fix(r, "最后手段：重启后再删除；或用 Process Explorer 的“句柄搜索(Handle → Find Handle)”定位持有者");
    return r->restricted ? 1 : 0;
}

#endif /* _WIN32 */

/* ================= POSIX（macOS / Linux） ================= */
#ifndef _WIN32

static void posix_err_text(int e, char *out, size_t n)
{
    switch (e) {
    case EACCES:       snprintf(out, n, "权限不足（读写执行位不允许，或 macOS 隐私保护 TCC 拦截）"); break;
    case EPERM:        snprintf(out, n, "操作被禁止（SIP 系统完整性保护 / immutable 标志 / 安全策略）"); break;
    case EROFS:        snprintf(out, n, "文件系统只读挂载"); break;
    case ETXTBSY:      snprintf(out, n, "文本忙：文件正被作为可执行程序运行"); break;
    case EBUSY:        snprintf(out, n, "资源忙：正被占用（挂载点/交换文件/被进程独占）"); break;
    case ENOENT:       snprintf(out, n, "路径不存在"); break;
    case ENOTDIR:      snprintf(out, n, "路径中包含非目录成分"); break;
    case EISDIR:       snprintf(out, n, "目标是目录"); break;
    case ENOTEMPTY:    snprintf(out, n, "目录非空"); break;
    case ENAMETOOLONG: snprintf(out, n, "路径/文件名过长"); break;
    case ELOOP:        snprintf(out, n, "符号链接循环"); break;
    default:           snprintf(out, n, "%s", strerror(e)); break;
    }
}

static int run_lsof(const char *path, Locker *out, int max, int deep)
{
    char q[4096], cmd[8200];
    shell_quote(path, q, sizeof(q));
    if (deep) snprintf(cmd, sizeof(cmd), "lsof -F pcu +D %s 2>/dev/null", q);
    else      snprintf(cmd, sizeof(cmd), "lsof -F pcu -- %s 2>/dev/null", q);

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    char line[512];
    int count = 0;
    long cur = -1;
    char curname[256] = "";
    char curuser[128] = "";
    for (;;) {
        if (!fgets(line, sizeof(line), fp)) break;
        size_t l = strlen(line);
        while (l && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = 0;
        if (l < 2) continue;
        if (line[0] == 'p') {
            if (cur > 0 && count < max) {
                int dup = 0;
                for (int i = 0; i < count; i++) if (out[i].pid == cur) { dup = 1; break; }
                if (!dup) {
                    out[count].pid = cur;
                    snprintf(out[count].name, sizeof(out[count].name), "%.*s",
                             (int)sizeof(out[count].name) - 1, curname);
                    if (curuser[0])
                        snprintf(out[count].detail, sizeof(out[count].detail), "lsof · 用户 %s", curuser);
                    else
                        snprintf(out[count].detail, sizeof(out[count].detail), "lsof 扫描");
                    count++;
                }
            }
            cur = atol(line + 1);
            curname[0] = 0;
            curuser[0] = 0;
        } else if (line[0] == 'c' && cur > 0 && !curname[0]) {
            snprintf(curname, sizeof(curname), "%.*s", (int)sizeof(curname) - 1, line + 1);
        } else if (line[0] == 'u' && cur > 0 && !curuser[0]) {
            snprintf(curuser, sizeof(curuser), "%.*s", (int)sizeof(curuser) - 1, line + 1);
        }
    }
    if (cur > 0 && count < max) {
        int dup = 0;
        for (int i = 0; i < count; i++) if (out[i].pid == cur) { dup = 1; break; }
        if (!dup) {
            out[count].pid = cur;
            snprintf(out[count].name, sizeof(out[count].name), "%.*s",
                     (int)sizeof(out[count].name) - 1, curname);
            if (curuser[0])
                snprintf(out[count].detail, sizeof(out[count].detail), "lsof · 用户 %s", curuser);
            else
                snprintf(out[count].detail, sizeof(out[count].detail), "lsof 扫描");
            count++;
        }
    }
    pclose(fp);
    return count;
}

#ifdef __linux__
static void proc_user(long pid, char *out, size_t n)
{
    out[0] = 0;
    char p[64];
    struct stat st;
    snprintf(p, sizeof(p), "/proc/%ld", pid);
    if (stat(p, &st) == 0) {
        struct passwd *pw = getpwuid(st.st_uid);
        if (pw) snprintf(out, n, "%s", pw->pw_name);
        else snprintf(out, n, "%d", (int)st.st_uid);
    }
}

static int proc_scan(const char *path, Locker *out, int max, int is_dir, int deep)
{
    DIR *d = opendir("/proc");
    if (!d) return -1;
    int count = 0;
    struct dirent *de;
    char target[4096], link[768];
    size_t plen = strlen(path);
    while ((de = readdir(d)) != NULL && count < max) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        long pid = atol(de->d_name);
        if (pid <= 0) continue;

        const char *tags[2] = { "cwd", "exe" };
        for (int t = 0; t < 2 && count < max; t++) {
            snprintf(link, sizeof(link), "/proc/%.200s/%s", de->d_name, tags[t]);
            ssize_t n = readlink(link, target, sizeof(target) - 1);
            if (n <= 0) continue;
            target[n] = 0;
            int hit = 0;
            if (strcmp(target, path) == 0) hit = 1;
            else if (deep && is_dir && strncmp(target, path, plen) == 0 &&
                     (target[plen] == '/' || target[plen] == 0)) hit = 1;
            if (!hit) continue;
            int dup = 0;
            for (int i = 0; i < count; i++) if (out[i].pid == pid) { dup = 1; break; }
            if (dup) continue;
            out[count].pid = pid;
            snprintf(out[count].name, sizeof(out[count].name), "%.*s",
                     (int)sizeof(out[count].name) - 1, base_name(link)); /* 占位，下面覆盖 */
            {
                char comm[128] = "?";
                snprintf(link, sizeof(link), "/proc/%.200s/comm", de->d_name);
                FILE *cf = fopen(link, "r");
                if (cf) {
                    if (fgets(comm, sizeof(comm), cf)) {
                        size_t L = strlen(comm);
                        while (L && (comm[L-1] == '\n' || comm[L-1] == '\r')) comm[--L] = 0;
                    }
                    fclose(cf);
                }
                snprintf(out[count].name, sizeof(out[count].name), "%.*s",
                         (int)sizeof(out[count].name) - 1, comm);
            }
            {
                char user[64] = "";
                proc_user(pid, user, sizeof(user));
                if (user[0])
                    snprintf(out[count].detail, sizeof(out[count].detail), "通过 %s · 用户 %s", tags[t], user);
                else
                    snprintf(out[count].detail, sizeof(out[count].detail), "通过 %s", tags[t]);
            }
            count++;
        }

        char fddir[512];
        snprintf(fddir, sizeof(fddir), "/proc/%.200s/fd", de->d_name);
        DIR *fd = opendir(fddir);
        if (!fd) continue;
        struct dirent *fe;
        while ((fe = readdir(fd)) != NULL && count < max) {
            if (fe->d_name[0] == '.') continue;
            snprintf(link, sizeof(link), "%s/%.200s", fddir, fe->d_name);
            ssize_t n = readlink(link, target, sizeof(target) - 1);
            if (n <= 0) continue;
            target[n] = 0;
            if (strncmp(target, path, plen) != 0) continue;
            if (!(target[plen] == 0 || target[plen] == ' ' || (deep && is_dir && target[plen] == '/'))) continue;
            int dup = 0;
            for (int i = 0; i < count; i++) if (out[i].pid == pid) { dup = 1; break; }
            if (dup) continue;
            char comm[128] = "?";
            snprintf(link, sizeof(link), "/proc/%.200s/comm", de->d_name);
            FILE *cf = fopen(link, "r");
            if (cf) {
                if (fgets(comm, sizeof(comm), cf)) {
                    size_t L = strlen(comm);
                    while (L && (comm[L-1] == '\n' || comm[L-1] == '\r')) comm[--L] = 0;
                }
                fclose(cf);
            }
            out[count].pid = pid;
            snprintf(out[count].name, sizeof(out[count].name), "%.*s",
                     (int)sizeof(out[count].name) - 1, comm);
            {
                char user[64] = "";
                proc_user(pid, user, sizeof(user));
                if (user[0])
                    snprintf(out[count].detail, sizeof(out[count].detail), "fd %.180s · 用户 %s", fe->d_name, user);
                else
                    snprintf(out[count].detail, sizeof(out[count].detail), "fd %.200s", fe->d_name);
            }
            count++;
        }
        closedir(fd);
    }
    closedir(d);
    return count;
}
#endif

int kill_locker(const Locker *L)
{
    return kill((pid_t)L->pid, SIGTERM) == 0 ? 0 : -1;
}

static int diag_posix(const char *path, Report *r, int deep)
{
    struct stat st, lst;

    if (lstat(path, &lst) != 0) {
        int e = errno;
        char t[256]; posix_err_text(e, t, sizeof(t));
        report_add_reason(r, "路径不存在或无法访问：%s（errno %d）", t, e);
        report_add_fix(r, "确认路径拼写与挂载状态；macOS 上确认已授予应用“完全磁盘访问权限”");
        return 2;
    }
    r->exists = 1;
    r->is_link = S_ISLNK(lst.st_mode);
    if (stat(path, &st) != 0) {
        int e = errno;
        char t[256]; posix_err_text(e, t, sizeof(t));
        report_add_reason(r, "符号链接指向的目标不可用：%s", t);
        report_add_fix(r, "修复或重新创建链接目标");
        return 2;
    }
    r->is_dir = S_ISDIR(st.st_mode);
    r->size = (long long)st.st_size;

    if (access(path, R_OK) != 0) {
        char t[256]; posix_err_text(errno, t, sizeof(t));
        report_add_reason(r, "无读取权限：%s（模式 %04o）", t, (unsigned)(st.st_mode & 07777));
        report_add_fix(r, "chmod u+r \"%s\"   或用 sudo/chown 修正归属", path);
        r->restricted = 1;
    } else r->can_read = 1;

    if (access(path, W_OK) != 0) {
        char t[256]; posix_err_text(errno, t, sizeof(t));
        report_add_reason(r, "无写入权限：%s（模式 %04o，uid=%d gid=%d）",
                          t, (unsigned)(st.st_mode & 07777), (int)st.st_uid, (int)st.st_gid);
        report_add_fix(r, "chmod u+w \"%s\"   或检查属主：ls -l \"%s\"", path, path);
        r->restricted = 1;
    } else r->can_write = 1;

#if defined(__APPLE__) || defined(__linux__)
    {
        struct statfs sfs;
        if (statfs(path, &sfs) == 0 && (sfs.f_flags & MNT_RDONLY)) {
            report_add_reason(r, "所在文件系统以只读方式挂载（介质写保护或系统卷只读）");
            report_add_fix(r, "macOS：系统卷默认只读(SIP)，请把文件放到用户目录操作");
            r->restricted = 1;
        }
    }
#endif

#if defined(__APPLE__)
    if (lst.st_flags & (SF_IMMUTABLE | UF_IMMUTABLE)) {
        report_add_reason(r, "文件被标记为不可变(immutable)，即使 root 也不能删除/修改");
        report_add_fix(r, "解除标志：sudo chflags nouimmutable \"%s\"", path);
        r->restricted = 1;
    }
    if (lst.st_flags & SF_APPEND) {
        report_add_reason(r, "文件被标记为仅可追加(SF_APPEND)");
        report_add_fix(r, "解除标志：sudo chflags noappnd \"%s\"", path);
    }
    if (strncmp(path, "/System", 7) == 0 || strncmp(path, "/usr", 4) == 0 ||
        strncmp(path, "/bin", 4) == 0 || strncmp(path, "/sbin", 5) == 0) {
        report_add_reason(r, "该路径位于 macOS SIP 系统完整性保护范围，系统拒绝任何修改");
        report_add_fix(r, "不要修改系统目录；把要处理的文件放到用户目录");
        r->restricted = 1;
    }
    if (strstr(path, "/Desktop") || strstr(path, "/Documents") || strstr(path, "/Downloads") ||
        strstr(path, "/Pictures") || strstr(path, "/Music") || strstr(path, "/Movies")) {
        report_add_reason(r, "可能受 macOS 隐私保护(TCC)限制：应用未被授权访问桌面/文稿等目录");
        report_add_fix(r, "系统设置 → 隐私与安全性 → 完全磁盘访问权限，给应用打勾");
    }
#endif

#ifdef __linux__
    {
        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd >= 0) {
            long flags = 0;
            if (ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0 && (flags & FS_IMMUTABLE_FL)) {
                report_add_reason(r, "文件被标记为不可变标志(immutable)");
                report_add_fix(r, "解除标志：sudo chattr -i \"%s\"", path);
                r->restricted = 1;
            }
            close(fd);
        }
    }
#endif

    {
        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            int e = errno;
            char t[256]; posix_err_text(e, t, sizeof(t));
            report_add_reason(r, "无法打开读取：%s（errno %d）", t, e);
            r->restricted = 1;
        } else close(fd);
    }
    if (!r->is_dir) {
        int fd = open(path, O_WRONLY | O_NONBLOCK);
        if (fd < 0) {
            int e = errno;
            char t[256]; posix_err_text(e, t, sizeof(t));
            report_add_reason(r, "无法以写方式打开：%s（errno %d）", t, e);
            if (e == ETXTBSY) {
                report_add_reason(r, "该文件当前正在被执行/运行");
                report_add_fix(r, "先停止运行该程序，再覆盖或删除它");
            }
            if (e == EROFS) report_add_fix(r, "文件系统只读：检查磁盘错误或重新以读写方式挂载");
            r->restricted = 1;
        } else close(fd);
    }

    {
        char parent[4096];
        dir_name(path, parent, sizeof(parent));
        if (access(parent, W_OK | X_OK) != 0) {
            char t[256]; posix_err_text(errno, t, sizeof(t));
            report_add_reason(r, "父目录不可写，无法删除/重命名：%s（%s）", t, parent);
            report_add_fix(r, "chmod u+w \"%s\"   或使用 sudo 操作", parent);
            r->restricted = 1;
        } else r->can_delete = 1;
    }

    char abspath[4096];
    if (!realpath(path, abspath)) snprintf(abspath, sizeof(abspath), "%s", path);

    int n = -1;
    FILE *chk = popen("command -v lsof >/dev/null 2>&1", "r");
    int has_lsof = chk && (pclose(chk) == 0);
    if (has_lsof) n = run_lsof(abspath, r->lockers, MAX_LOCKERS, deep && r->is_dir);
#ifdef __linux__
    if (n <= 0) n = proc_scan(abspath, r->lockers, MAX_LOCKERS, r->is_dir, deep);
#endif

    if (n > 0) {
        r->nlockers = n;
        r->restricted = 1;
        for (int i = 0; i < n; i++)
            report_add_reason(r, "被进程占用：%s (PID %ld)",
                              r->lockers[i].name[0] ? r->lockers[i].name : "(未知)", r->lockers[i].pid);
        report_add_fix(r, "确认无用后：kill %ld   或命令行模式  filelock -k \"%s\"", r->lockers[0].pid, path);
        report_add_fix(r, "查看完整占用详情：sudo lsof -- \"%s\"", abspath);
    } else if (n == 0) {
        if (r->restricted)
            report_add_reason(r, "未发现用户态进程占用，可能是：内核态持有（挂载点/交换文件/NFS 租约）或权限不足");
        if (r->restricted)
            report_add_fix(r, "用 root 重扫：sudo lsof -- \"%s\"", abspath);
    } else {
        report_add_fix(r, "占用扫描不可用：请安装 lsof（macOS 自带；Debian/Ubuntu: sudo apt install lsof）");
    }

    if (r->is_dir) {
        report_add_fix(r, "目录删除失败常见原因：① 目录内还有文件被打开 ② 目录是某进程工作目录(cwd) ③ 存在挂载点");
        report_add_fix(r, "检查挂载点：mount | grep \"%s\"", abspath);
    }
    return r->restricted ? 1 : 0;
}

#endif /* !_WIN32 */

int diagnose_path(const char *path, Report *r, int deep)
{
    memset(r, 0, sizeof(*r));
#ifdef _WIN32
    return diag_windows(path, r, deep);
#else
    return diag_posix(path, r, deep);
#endif
}

/* ---------------- 命令行报告 ---------------- */

void print_report(const char *path, const Report *r)
{
    char unit[8];
    long long sz = human_size(r->size, unit, sizeof(unit));

    printf("\n========================================================\n");
    printf(" 文件占用诊断报告\n");
    printf("========================================================\n");
    printf("[0] 目标信息\n");
    printf("    路径 : %s\n", path);
    if (!r->exists) {
        printf("    状态 : 不存在或无法访问\n");
    } else {
        printf("    类型 : %s%s\n", r->is_dir ? "目录" : "文件", r->is_link ? "（符号链接）" : "");
        if (!r->is_dir) printf("    大小 : %lld %s\n", sz, unit);
        printf("    权限 : 读[%s]  写[%s]  删除/改名[%s]\n",
               r->can_read ? "✓" : "✗", r->can_write ? "✓" : "✗", r->can_delete ? "✓" : "✗");
    }

    if (r->nlockers > 0) {
        printf("\n[1] 占用进程（共 %d 个）\n", r->nlockers);
        printf("    %-8s %-28s %s\n", "PID", "进程名", "路径/说明");
        printf("    %-8s %-28s %s\n", "--------", "----------------------------", "--------------------");
        for (int i = 0; i < r->nlockers; i++)
            printf("    %-8ld %-28s %s\n", r->lockers[i].pid,
                   r->lockers[i].name[0] ? r->lockers[i].name : "(未知)",
                   r->lockers[i].detail[0] ? r->lockers[i].detail : "-");
    }

    printf("\n[2] 原因分析\n");
    if (r->nreasons == 0) printf("    未发现明显问题，可正常读写删除。\n");
    else for (int i = 0; i < r->nreasons; i++) printf("    %d) %s\n", i + 1, r->reasons[i]);

    printf("\n[3] 解决办法\n");
    if (r->nfixes == 0) printf("    无需处理。\n");
    else for (int i = 0; i < r->nfixes; i++) printf("    %d) %s\n", i + 1, r->fixes[i]);

    printf("\n[4] 结论\n");
    if (!r->exists) printf("    路径不存在。\n");
    else if (r->nlockers > 0) printf("    ✔ 找到 %d 个占用进程 —— 关闭它们即可解除占用。\n", r->nlockers);
    else if (r->restricted) printf("    ✔ 找到受限原因（见上），按建议逐条处理。\n");
    else printf("    ✔ 该路径当前没有被占用。\n");
    printf("========================================================\n");
}
