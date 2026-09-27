/*
 * filelock — 文件占用诊断工具
 * ---------------------------------------------------------------
 * 功能：诊断“文件/文件夹被占用、无法删除、无法写入、无法重命名”的原因，
 *       列出占用进程，并给出针对性的解决办法。支持 Windows / macOS
 *       （Linux 亦可编译，便于测试）。
 *
 * 用法：
 *   filelock [选项] <文件或目录路径>
 *
 * 选项：
 *   -v        详细模式（输出原始错误码、系统细节）
 *   -k        结束占用进程（危险操作，请先用默认模式确认目标）
 *   -d        对目录递归检查其中被打开的文件（macOS/Linux 用 lsof +D）
 *   -h        显示帮助
 *
 * 编译：
 *   Windows (MSVC) :  cl /O2 /W3 filelock.c rstrtmgr.lib
 *   Windows (MinGW):  gcc -O2 -Wall filelock.c -o filelock.exe -lrstrtmgr
 *   macOS          :  clang -O2 -Wall filelock.c -o filelock
 *   Linux (测试)   :  gcc -O2 -Wall filelock.c -o filelock
 *
 * 退出码：0=无占用 1=发现占用/受限 2=路径不存在 3=参数错误 4=系统调用失败
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601   /* Windows 7+，保证 Restart Manager / QueryFullProcessImageName 可用 */
#  endif
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <restartmanager.h>
#  ifdef _MSC_VER
#    pragma comment(lib, "rstrtmgr.lib")
#  endif
#else
#  include <unistd.h>
#  include <fcntl.h>
#  include <signal.h>
#  include <dirent.h>
#  include <strings.h>
#  if defined(__APPLE__)
#    include <sys/param.h>
#    include <sys/mount.h>
#  elif defined(__linux__)
#    include <sys/vfs.h>
#    include <sys/mount.h>
#    include <sys/ioctl.h>
#    include <linux/fs.h>
#  endif
#endif

/* BSD/macOS 文件标志（头文件可能未提供，给回退值） */
#ifndef SF_IMMUTABLE
#  define SF_IMMUTABLE 0x00020000
#endif
#ifndef UF_IMMUTABLE
#  define UF_IMMUTABLE 0x00000002
#endif
#ifndef SF_APPEND
#  define SF_APPEND 0x00040000
#endif
#ifndef MNT_RDONLY
#  define MNT_RDONLY 0x00000001
#endif

#define MAX_ITEMS 24
#define ITEM_LEN   512

typedef struct {
    char reasons[MAX_ITEMS][ITEM_LEN];
    int  nreasons;
    char fixes[MAX_ITEMS][ITEM_LEN];
    int  nfixes;

    int  exists;
    int  is_dir;
    int  is_link;
    int  can_read;
    int  can_write;
    int  can_delete;
    int  restricted;      /* 至少一项受限 */
    int  lockers;         /* 占用进程数 */
    long long size;
} Report;

typedef struct {
    long pid;
    char name[128];
    char detail[256];
} Locker;

static int g_verbose = 0;
static int g_kill = 0;
static int g_deep = 0;

/* ---------------- 基础工具 ---------------- */

#ifdef __GNUC__
#  define UNUSED_FN __attribute__((unused))
#else
#  define UNUSED_FN
#endif

static void add_item(char arr[][ITEM_LEN], int *n, const char *fmt, ...)
{
    if (*n >= MAX_ITEMS) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(arr[*n], ITEM_LEN, fmt, ap);
    va_end(ap);
    (*n)++;
}

static void add_reason(Report *r, const char *fmt, ...)
{
    if (r->nreasons >= MAX_ITEMS) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->reasons[r->nreasons], ITEM_LEN, fmt, ap);
    va_end(ap);
    r->nreasons++;
}

static void add_fix(Report *r, const char *fmt, ...)
{
    if (r->nfixes >= MAX_ITEMS) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->fixes[r->nfixes], ITEM_LEN, fmt, ap);
    va_end(ap);
    r->nfixes++;
}

static int is_dup_fix(Report *r, const char *text)
{
    for (int i = 0; i < r->nfixes; i++)
        if (strcmp(r->fixes[i], text) == 0) return 1;
    return 0;
}

UNUSED_FN static void add_fix_once(Report *r, const char *fmt, ...)
{
    char buf[ITEM_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (!is_dup_fix(r, buf)) add_item(r->fixes, &r->nfixes, "%s", buf);
}

/* 把路径塞进单引号 shell 参数（用于 lsof） */
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
    while (len > 0 && out[len - 1] != '/' && out[len - 1] != '\\') { out[--len] = 0; }
    if (len == 0) snprintf(out, n, ".");
    else if (len > 1) out[len - 1] = 0;   /* 去掉尾部斜杠（保留根 "/"） */
}

static long long human_size(long long b, char *unit, size_t un)
{
    if (b >= 1024LL * 1024 * 1024) { snprintf(unit, un, "GB"); return b / (1024LL * 1024 * 1024); }
    if (b >= 1024LL * 1024)        { snprintf(unit, un, "MB"); return b / (1024LL * 1024); }
    if (b >= 1024LL)               { snprintf(unit, un, "KB"); return b / 1024; }
    snprintf(unit, un, "B");
    return b;
}

/* ================= Windows 实现 ================= */
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
    case ERROR_LOCK_VIOLATION:     snprintf(out, n, "字节区域被其他进程锁定（如数据库/下载工具）"); break;
    case ERROR_USER_MAPPED_FILE:   snprintf(out, n, "文件被映射进某进程的内存（内存映射占用）"); break;
    case ERROR_ACCESS_DENIED:      snprintf(out, n, "拒绝访问（权限不足 / 只读属性 / 系统保护 / 安全软件）"); break;
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
    case ERROR_SHARING_BUFFER_EXCEEDED: snprintf(out, n, "共享缓冲区超限"); break;
    default: {
        LPWSTR lpMsg = NULL;
        DWORD n2 = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                  FORMAT_MESSAGE_IGNORE_INSERTS, NULL, e, 0, (LPWSTR)&lpMsg, 0, NULL);
        if (n2 && lpMsg) {
            char tmp[256];
            utf8_from_wide(lpMsg, tmp, sizeof(tmp));
            /* 去掉末尾换行 */
            size_t l = strlen(tmp);
            while (l && (tmp[l-1] == '\r' || tmp[l-1] == '\n')) tmp[--l] = 0;
            snprintf(out, n, "%s", tmp);
            LocalFree(lpMsg);
        } else snprintf(out, n, "未知错误");
        break;
    }
    }
}

/* 尝试以指定访问方式打开，返回 0=成功，否则返回 GetLastError() */
static DWORD try_open(const WCHAR *wpath, DWORD access, DWORD share, int dir)
{
    DWORD flags = dir ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL;
    HANDLE h = CreateFileW(wpath, access, share, NULL, OPEN_EXISTING, flags, NULL);
    if (h == INVALID_HANDLE_VALUE) return GetLastError();
    CloseHandle(h);
    return 0;
}

/* 通过 Restart Manager 查找占用进程 */
static int win_find_lockers(const WCHAR *wpath, Locker *out, int max, Report *r)
{
    DWORD sess = 0;
    WCHAR key[CCH_RM_SESSION_KEY + 1] = { 0 };
    DWORD res = RmStartSession(&sess, 0, key);
    if (res != ERROR_SUCCESS) {
        if (g_verbose) printf("  (Restart Manager 会话启动失败, 错误 %lu)\n", (unsigned long)res);
        return -1;
    }

    const WCHAR *pw = wpath;
    res = RmRegisterResources(sess, 1, &pw, 0, NULL, 0, NULL);
    if (res != ERROR_SUCCESS) {
        if (g_verbose) printf("  (资源注册失败, 错误 %lu)\n", (unsigned long)res);
        RmEndSession(sess);
        return -1;
    }

    UINT needed = 0, got = 0;
    DWORD reason = 0;
    RM_PROCESS_INFO *info = NULL;
    res = RmGetList(sess, &needed, &got, NULL, &reason);
    if (res == ERROR_MORE_DATA && needed > 0) {
        info = (RM_PROCESS_INFO *)calloc(needed, sizeof(RM_PROCESS_INFO));
        if (info) {
            got = needed;
            res = RmGetList(sess, &needed, &got, info, &reason);
            if (res != ERROR_SUCCESS) { free(info); info = NULL; got = 0; }
        }
    } else if (res == ERROR_SUCCESS) {
        got = 0;
    }

    int count = 0;
    for (UINT i = 0; i < got && count < max; i++) {
        Locker *L = &out[count];
        L->pid = (long)info[i].Process.dwProcessId;
        utf8_from_wide(info[i].strAppName, L->name, sizeof(L->name));
        char extra[128] = "";
        switch (info[i].ApplicationType) {
        case RmCritical:     snprintf(extra, sizeof(extra), "关键系统进程（不可安全终止）"); break;
        case RmService:      snprintf(extra, sizeof(extra), "Windows 服务"); break;
        case RmExplorer:     snprintf(extra, sizeof(extra), "资源管理器"); break;
        case RmConsole:      snprintf(extra, sizeof(extra), "控制台程序"); break;
        case RmMainWindow:
        case RmOtherWindow:  snprintf(extra, sizeof(extra), "图形界面程序"); break;
        default: break;
        }
        if (info[i].bAppType && !extra[0]) snprintf(extra, sizeof(extra), "系统/服务应用");
        if (info[i].strServiceShortName[0]) {
            char svc[64];
            utf8_from_wide(info[i].strServiceShortName, svc, sizeof(svc));
            snprintf(extra + strlen(extra), sizeof(extra) - strlen(extra), "[%s]", svc);
        }
        /* 尝试取真实可执行文件路径 */
        HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info[i].Process.dwProcessId);
        if (hp) {
            WCHAR wexe[MAX_PATH * 2] = { 0 };
            DWORD sz = MAX_PATH * 2;
            if (QueryFullProcessImageNameW(hp, 0, wexe, &sz)) {
                char exe[MAX_PATH * 2];
                utf8_from_wide(wexe, exe, sizeof(exe));
                snprintf(L->detail, sizeof(L->detail), "%s%s%s", exe, extra[0] ? " | " : "", extra);
            } else snprintf(L->detail, sizeof(L->detail), "%s", extra);
            CloseHandle(hp);
        } else snprintf(L->detail, sizeof(L->detail), "%s", extra);
        count++;
    }
    free(info);
    RmEndSession(sess);
    return count;
}

static int win_kill_pid(long pid)
{
    HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (!hp) { printf("  ✗ 无法打开进程 %ld（错误 %lu）\n", pid, (unsigned long)GetLastError()); return -1; }
    if (TerminateProcess(hp, 1)) { printf("  ✓ 已结束进程 %ld\n", pid); CloseHandle(hp); return 0; }
    printf("  ✗ 结束进程 %ld 失败（错误 %lu）\n", pid, (unsigned long)GetLastError());
    CloseHandle(hp);
    return -1;
}

static void diag_windows(const char *path, Report *r)
{
    WCHAR wpath[32768];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 32768)) {
        MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, 32768);
    }

    DWORD attr = GetFileAttributesW(wpath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD e = GetLastError();
        char t[256]; win_err_text(e, t, sizeof(t));
        r->exists = 0;
        add_reason(r, "路径不存在或无法访问：%s（错误 %lu）", t, (unsigned long)e);
        add_fix(r, "确认路径拼写；若是网络/移动盘，检查设备是否已连接");
        if (e == ERROR_FILENAME_EXCED_RANGE || strlen(path) > 260)
            add_fix(r, "路径过长：启用长路径支持，或把文件移到较短目录，或用 \\\\?\\ 前缀");
        return;
    }
    r->exists = 1;
    r->is_dir = (attr & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
    r->is_link = (attr & FILE_ATTRIBUTE_REPARSE_POINT) ? 1 : 0;

    /* --- 属性检查 --- */
    if (attr & FILE_ATTRIBUTE_READONLY) {
        r->restricted = 1;
        add_reason(r, "文件带有“只读”属性 (FILE_ATTRIBUTE_READONLY)");
        add_fix(r, "取消只读属性：attrib -R \"%s\"", path);
    }
    if (attr & FILE_ATTRIBUTE_SYSTEM) add_reason(r, "文件带“系统”属性，Windows 对其有额外保护");
    if (attr & FILE_ATTRIBUTE_HIDDEN) { /* 仅提示 */ }
    if (attr & FILE_ATTRIBUTE_OFFLINE) {
        add_reason(r, "文件处于“脱机”状态（被移到离线存储，内容不在本地磁盘上）");
        add_fix(r, "先把文件恢复到本地：右键 → 属性 → 取消“脱机”/“压缩内容以节省磁盘空间”");
    }
    if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
        add_reason(r, "这是链接/联接点(符号链接或目录联接)，操作会作用到目标上");
        add_fix(r, "确认目标路径：%s 的真实位置（dir /AL 或 Get-Item | Select LinkType,Target）", path);
    }
    if (attr & FILE_ATTRIBUTE_ENCRYPTED) add_reason(r, "文件使用 EFS 加密，换账号访问会被拒绝");

    /* --- 访问测试 --- */
    DWORD shareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    DWORD e;

    e = try_open(wpath, GENERIC_READ, shareAll, r->is_dir);
    if (e == 0) r->can_read = 1;
    else {
        char t[256]; win_err_text(e, t, sizeof(t));
        add_reason(r, "无法读取：%s（错误 %lu）", t, (unsigned long)e);
    }

    if (!r->is_dir) {
        e = try_open(wpath, GENERIC_WRITE, shareAll, 0);
        if (e == 0) r->can_write = 1;
        else {
            char t[256]; win_err_text(e, t, sizeof(t));
            add_reason(r, "无法写入：%s（错误 %lu）", t, (unsigned long)e);
            if (e == ERROR_SHARING_VIOLATION || e == ERROR_LOCK_VIOLATION)
                r->restricted = 1;
            if (e == ERROR_USER_MAPPED_FILE) {
                add_reason(r, "典型场景：程序正在加载该 DLL/数据文件，或页面文件、虚拟内存占用");
                add_fix(r, "结束相关程序后重试；若是 .dll/.exe，请重启后再操作");
            }
            if (e == ERROR_ACCESS_DENIED)
                add_fix(r, "右键 → 属性 → 安全 → 检查当前账号的写入权限；或用管理员身份运行本工具");
        }
    }

    e = try_open(wpath, DELETE, shareAll, r->is_dir);
    if (e == 0) r->can_delete = 1;
    else {
        char t[256]; win_err_text(e, t, sizeof(t));
        add_reason(r, "无法删除/重命名：%s（错误 %lu）", t, (unsigned long)e);
        r->restricted = 1;
        switch (e) {
        case ERROR_CURRENT_DIRECTORY:
            add_fix(r, "该目录是某进程的工作目录：关闭对应程序，或让其 chdir 到别处（资源管理器尤其常见）");
            break;
        case ERROR_SHARING_VIOLATION:
        case ERROR_LOCK_VIOLATION:
            add_fix(r, "关闭正在使用它的程序（见下方占用进程列表）后重试");
            break;
        case ERROR_ACCESS_DENIED:
            add_fix(r, "以管理员身份运行命令提示符/PowerShell 再操作");
            add_fix(r, "检查是否有安全软件（杀毒/EDR/DLP）正在扫描或锁定该文件");
            break;
        case ERROR_DELETE_PENDING:
            add_fix(r, "稍等片刻；重启后该文件会自动消失");
            break;
        }
    }

    /* --- 占用进程 --- */
    Locker lockers[32];
    int n = win_find_lockers(wpath, lockers, 32, r);
    if (n > 0) {
        r->lockers = n;
        r->restricted = 1;
        printf("\n[2] 占用进程（Restart Manager 扫描结果，共 %d 个）\n", n);
        printf("    %-8s %-28s %s\n", "PID", "进程名", "路径/说明");
        printf("    %-8s %-28s %s\n", "--------", "----------------------------",
               "----------------------------------------");
        for (int i = 0; i < n; i++) {
            printf("    %-8ld %-28s %s\n", lockers[i].pid,
                   lockers[i].name[0] ? lockers[i].name : "(未知)",
                   lockers[i].detail[0] ? lockers[i].detail : "-");
            add_reason(r, "被进程占用：%s (PID %ld)", lockers[i].name[0] ? lockers[i].name : "(未知)", lockers[i].pid);
        }
        if (g_kill) {
            printf("\n    -- 正在结束占用进程 (-k) --\n");
            for (int i = 0; i < n; i++) win_kill_pid(lockers[i].pid);
            Sleep(800);
            e = try_open(wpath, DELETE, shareAll, r->is_dir);
            printf("    复测：%s\n", e == 0 ? "已解除占用，可以删除/重命名了" : "仍被占用（可能有内核态句柄或需要重启）");
            add_fix(r, "已强制结束 %d 个进程；若文件仍被占用，请重启后再操作", n);
        } else {
            add_fix(r, "安全关闭这些程序后重试；确认无用时可用  filelock -k \"%s\"  强制结束占用进程", path);
        }
    } else if (n == 0) {
        printf("\n[2] 占用进程（Restart Manager 扫描结果）\n");
        printf("    未发现持有句柄的普通进程。\n");
        add_reason(r, "未发现普通进程句柄，可能是：内核驱动、杀毒软件、Windows Search 索引器、系统还原或资源管理器预览窗格");
        add_fix(r, "关闭资源管理器预览窗格（查看 → 预览窗格），稍等索引/扫描结束后重试");
        add_fix(r, "重启资源管理器：taskkill /f /im explorer.exe && start explorer.exe");
    } else {
        printf("\n[2] 占用进程\n    扫描失败（权限不足？可尝试以管理员身份运行）\n");
        add_fix(r, "以管理员身份重新运行本工具以获取占用进程列表");
    }

    /* --- 常见兜底建议 --- */
    if (!r->can_delete && r->is_dir)
        add_fix(r, "目录删除失败常见原因：① 某程序以其为工作目录 ② 目录内有文件被打开 ③ 路径过长 ④ 资源管理器正预览");
    if (r->restricted)
        add_fix(r, "最后手段：重启后再删除；或用 Unlocker / Process Explorer 的“句柄搜索”定位持有者");
    add_fix(r, "PowerShell 自查：Get-Process | Where-Object { $_.Modules.FileName -like '*%s*' }", base_name(path));
}

#endif /* _WIN32 */

/* ================= POSIX 实现（macOS / Linux） ================= */
#ifndef _WIN32

static void posix_err_text(int e, char *out, size_t n)
{
    switch (e) {
    case EACCES:    snprintf(out, n, "权限不足（目录/文件的读写执行位不允许，或 macOS 隐私保护 TCC 拦截）"); break;
    case EPERM:     snprintf(out, n, "操作被禁止（SIP 系统完整性保护 / 文件标志 immutable / 安全策略）"); break;
    case EROFS:     snprintf(out, n, "文件系统只读挂载"); break;
    case ETXTBSY:   snprintf(out, n, "文本忙：文件正被作为可执行程序运行，无法写入"); break;
    case EBUSY:     snprintf(out, n, "资源忙：文件正被占用（挂载点/交换文件/被进程独占）"); break;
    case ENOENT:    snprintf(out, n, "路径不存在"); break;
    case ENOTDIR:   snprintf(out, n, "路径中包含非目录成分"); break;
    case EISDIR:    snprintf(out, n, "目标是目录"); break;
    case ENOTEMPTY: snprintf(out, n, "目录非空"); break;
    case ENAMETOOLONG: snprintf(out, n, "路径/文件名过长"); break;
    case ELOOP:     snprintf(out, n, "符号链接循环"); break;
    case EAGAIN:    snprintf(out, n, "资源暂时不可用（可能是 flock/lease 锁）"); break;
    default:        snprintf(out, n, "%s", strerror(e)); break;
    }
}

static int run_lsof(const char *path, Locker *out, int max, int deep)
{
    char q[4096], cmd[8200];
    shell_quote(path, q, sizeof(q));
    if (deep) snprintf(cmd, sizeof(cmd), "lsof -F pc +D %s 2>/dev/null", q);
    else      snprintf(cmd, sizeof(cmd), "lsof -F pc -- %s 2>/dev/null", q);

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    char line[512];
    int count = 0;
    long cur = -1;
    char curname[256] = "";
    while (fgets(line, sizeof(line), fp)) {
        size_t l = strlen(line);
        while (l && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = 0;
        if (l < 2) continue;
        if (line[0] == 'p') {
            /* 上一条记录落盘 */
            if (cur > 0 && count < max) {
                int dup = 0;
                for (int i = 0; i < count; i++) if (out[i].pid == cur) { dup = 1; break; }
                if (!dup) {
                    out[count].pid = cur;
                    snprintf(out[count].name, sizeof(out[count].name), "%.*s",
                             (int)sizeof(out[count].name) - 1, curname);
                    snprintf(out[count].detail, sizeof(out[count].detail), "%s", "lsof 扫描");
                    count++;
                }
            }
            cur = atol(line + 1);
            curname[0] = 0;
        } else if (line[0] == 'c' && cur > 0 && !curname[0]) {
            snprintf(curname, sizeof(curname), "%.*s", (int)sizeof(curname) - 1, line + 1);
        }
    }
    if (cur > 0 && count < max) {
        int dup = 0;
        for (int i = 0; i < count; i++) if (out[i].pid == cur) { dup = 1; break; }
        if (!dup) {
            out[count].pid = cur;
            snprintf(out[count].name, sizeof(out[count].name), "%.*s",
                     (int)sizeof(out[count].name) - 1, curname);
            snprintf(out[count].detail, sizeof(out[count].detail), "%s", "lsof 扫描");
            count++;
        }
    }
    pclose(fp);
    return count;
}

#ifdef __linux__
/* lsof 不可用时的 /proc 回退扫描 */
static int proc_scan(const char *path, Locker *out, int max, int is_dir)
{
    DIR *d = opendir("/proc");
    if (!d) return -1;
    int count = 0;
    struct dirent *de;
    char target[4096], link[4096];
    size_t plen = strlen(path);
    while ((de = readdir(d)) != NULL && count < max) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        long pid = atol(de->d_name);
        if (pid <= 0) continue;

        /* 检查 cwd / exe */
        const char *tags[2] = { "cwd", "exe" };
        for (int t = 0; t < 2 && count < max; t++) {
            snprintf(link, sizeof(link), "/proc/%s/%s", de->d_name, tags[t]);
            ssize_t n = readlink(link, target, sizeof(target) - 1);
            if (n <= 0) continue;
            target[n] = 0;
            int hit = 0;
            if (strcmp(target, path) == 0) hit = 1;
            else if (is_dir && strncmp(target, path, plen) == 0 &&
                     (target[plen] == '/' || target[plen] == 0)) hit = 1;
            if (hit) {
                char comm[128] = "?";
                snprintf(link, sizeof(link), "/proc/%s/comm", de->d_name);
                FILE *cf = fopen(link, "r");
                if (cf) { if (fgets(comm, sizeof(comm), cf)) {
                        size_t L = strlen(comm); while (L && (comm[L-1]=='\n'||comm[L-1]=='\r')) comm[--L]=0; }
                    fclose(cf); }
                out[count].pid = pid;
                snprintf(out[count].name, sizeof(out[count].name), "%.*s",
                         (int)sizeof(out[count].name) - 1, comm);
                snprintf(out[count].detail, sizeof(out[count].detail), "通过 %s", tags[t]);
                count++;
            }
        }
        /* 扫描 fd */
        char fddir[512];
        snprintf(fddir, sizeof(fddir), "/proc/%.200s/fd", de->d_name);
        DIR *fd = opendir(fddir);
        if (!fd) continue;
        struct dirent *fe;
        while ((fe = readdir(fd)) != NULL && count < max) {
            if (fe->d_name[0] == '.') continue;
            snprintf(link, sizeof(link), "%s/%s", fddir, fe->d_name);
            ssize_t n = readlink(link, target, sizeof(target) - 1);
            if (n <= 0) continue;
            target[n] = 0;
            /* 去掉 " (deleted)" 之类的后缀比较 */
            int hit = 0;
            if (strncmp(target, path, plen) == 0 &&
                (target[plen] == 0 || target[plen] == ' ' || (is_dir && target[plen] == '/'))) hit = 1;
            if (!hit) continue;
            int dup = 0;
            for (int i = 0; i < count; i++) if (out[i].pid == pid) { dup = 1; break; }
            if (dup) continue;
            char comm[128] = "?";
            snprintf(link, sizeof(link), "/proc/%s/comm", de->d_name);
            FILE *cf = fopen(link, "r");
            if (cf) { if (fgets(comm, sizeof(comm), cf)) {
                    size_t L = strlen(comm); while (L && (comm[L-1]=='\n'||comm[L-1]=='\r')) comm[--L]=0; }
                fclose(cf); }
            out[count].pid = pid;
            snprintf(out[count].name, sizeof(out[count].name), "%.*s",
                     (int)sizeof(out[count].name) - 1, comm);
            snprintf(out[count].detail, sizeof(out[count].detail), "fd %.200s", fe->d_name);
            count++;
        }
        closedir(fd);
    }
    closedir(d);
    return count;
}
#endif

static int posix_kill_pid(long pid)
{
    if (kill((pid_t)pid, SIGTERM) == 0) { printf("  ✓ 已向进程 %ld 发送 SIGTERM\n", pid); return 0; }
    printf("  ✗ 结束进程 %ld 失败：%s\n", pid, strerror(errno));
    return -1;
}

static void diag_posix(const char *path, Report *r)
{
    struct stat st;
    struct stat lst;

    if (lstat(path, &lst) != 0) {
        int e = errno;
        char t[256]; posix_err_text(e, t, sizeof(t));
        add_reason(r, "路径不存在或无法访问：%s（errno %d）", t, e);
        add_fix(r, "确认路径拼写与挂载状态；macOS 上确认已授予该终端“完全磁盘访问权限”");
        return;
    }
    r->exists = 1;
    r->is_link = S_ISLNK(lst.st_mode);
    if (stat(path, &st) != 0) {
        int e = errno;
        char t[256]; posix_err_text(e, t, sizeof(t));
        add_reason(r, "符号链接指向的目标不可用：%s", t);
        add_fix(r, "修复或重新创建链接目标");
        return;
    }
    r->is_dir = S_ISDIR(st.st_mode);
    r->size = (long long)st.st_size;

    /* 权限位 */
    if (access(path, R_OK) != 0) {
        char t[256]; posix_err_text(errno, t, sizeof(t));
        add_reason(r, "当前用户无读取权限：%s（模式 %04o）", t, (unsigned)(st.st_mode & 07777));
        add_fix(r, "chmod u+r \"%s\"  或  sudo chmod/chown 修正归属", path);
        r->restricted = 1;
    } else r->can_read = 1;

    if (access(path, W_OK) != 0) {
        char t[256]; posix_err_text(errno, t, sizeof(t));
        add_reason(r, "当前用户无写入权限：%s（模式 %04o，属主 uid=%d gid=%d）",
                   t, (unsigned)(st.st_mode & 07777), (int)st.st_uid, (int)st.st_gid);
        add_fix(r, "chmod u+w \"%s\"  或检查属主：ls -l \"%s\"", path, path);
        r->restricted = 1;
    } else r->can_write = 1;

    /* 只读文件系统 / 挂载状态 */
#if defined(__APPLE__) || defined(__linux__)
    {
        struct statfs sfs;
        if (statfs(path, &sfs) == 0) {
            if (sfs.f_flags & MNT_RDONLY) {
                add_reason(r, "所在文件系统以只读方式挂载（介质写保护或系统卷只读）");
                add_fix(r, "macOS：系统卷默认只读(SIP)，勿直接写 /System /usr；要写请放到用户目录");
                r->restricted = 1;
            }
        }
    }
#endif

    /* 文件标志（macOS/BSD immutable 等） */
#if defined(__APPLE__)
    if (lst.st_flags & SF_IMMUTABLE) {
        add_reason(r, "文件被标记为系统不可变 (SF_IMMUTABLE)，即使 root 也不能删除/修改");
        add_fix(r, "解除标志：sudo chflags nouimmutable \"%s\"", path);
        r->restricted = 1;
    }
    if (lst.st_flags & UF_IMMUTABLE) {
        add_reason(r, "文件被标记为用户不可变 (UF_IMMUTABLE)");
        add_fix(r, "解除标志：chflags nouimmutable \"%s\"", path);
        r->restricted = 1;
    }
    if (lst.st_flags & SF_APPEND) {
        add_reason(r, "文件被标记为仅可追加 (SF_APPEND)");
        add_fix(r, "解除标志：sudo chflags noappnd \"%s\"", path);
    }
    /* SIP 保护路径 */
    if (strncmp(path, "/System", 7) == 0 || strncmp(path, "/usr", 4) == 0 ||
        strncmp(path, "/bin", 4) == 0 || strncmp(path, "/sbin", 5) == 0 ||
        strncmp(path, "/private/var/db", 15) == 0) {
        add_reason(r, "该路径位于 macOS SIP(系统完整性保护) 保护范围内，系统会拒绝任何修改");
        add_fix(r, "不要修改系统目录；如确需修改，只能在恢复模式下 csrutil disable（不推荐）");
        r->restricted = 1;
    }
    /* TCC 隐私目录 */
    if (strstr(path, "/Desktop") || strstr(path, "/Documents") || strstr(path, "/Downloads") ||
        strstr(path, "/Pictures") || strstr(path, "/Music") || strstr(path, "/Movies")) {
        add_reason(r, "可能受 macOS 隐私保护(TCC)限制：终端/应用未被授权访问桌面、文稿等目录");
        add_fix(r, "系统设置 → 隐私与安全性 → 完全磁盘访问权限，为你的终端 App 打勾");
    }
#endif

#ifdef __linux__
    {
        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd >= 0) {
            long flags = 0;
            if (ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0 && (flags & FS_IMMUTABLE_FL)) {
                add_reason(r, "文件被标记为 ext 系列不可变标志 (immutable)");
                add_fix(r, "解除标志：sudo chattr -i \"%s\"", path);
                r->restricted = 1;
            }
            close(fd);
        }
    }
#endif

    /* 实际打开测试 */
    {
        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            int e = errno;
            char t[256]; posix_err_text(e, t, sizeof(t));
            add_reason(r, "无法打开读取：%s（errno %d）", t, e);
            r->restricted = 1;
        } else close(fd);
    }
    if (!r->is_dir) {
        int fd = open(path, O_WRONLY | O_NONBLOCK);
        if (fd < 0) {
            int e = errno;
            char t[256]; posix_err_text(e, t, sizeof(t));
            add_reason(r, "无法以写方式打开：%s（errno %d）", t, e);
            if (e == ETXTBSY) {
                add_reason(r, "该文件当前正在被执行/运行（ETXTBSY）");
                add_fix(r, "先停止运行该程序，再覆盖或删除它");
            }
            if (e == EROFS) add_fix(r, "文件系统只读：检查磁盘错误或重新以读写方式挂载");
            r->restricted = 1;
        } else close(fd);
    }

    /* 删除可行性：看父目录的写权限 */
    {
        char parent[4096];
        dir_name(path, parent, sizeof(parent));
        if (access(parent, W_OK | X_OK) != 0) {
            char t[256]; posix_err_text(errno, t, sizeof(t));
            add_reason(r, "父目录不可写，导致无法删除/重命名：%s（%s）", t, parent);
            add_fix(r, "chmod u+w \"%s\"  或使用 sudo 操作", parent);
            r->restricted = 1;
        } else {
            r->can_delete = 1;
        }
    }

    /* 占用进程扫描（用绝对路径匹配，避免相对路径失配） */
    Locker lockers[32];
    char abspath[4096];
    if (!realpath(path, abspath)) snprintf(abspath, sizeof(abspath), "%s", path);
    if (strcmp(abspath, path) != 0 && g_verbose)
        printf("(详细) 解析后的绝对路径: %s\n", abspath);
    int n = -1;
    FILE *chk = popen("command -v lsof >/dev/null 2>&1", "r");
    int has_lsof = 0;
    if (chk) { has_lsof = (pclose(chk) == 0); }
    if (has_lsof) n = run_lsof(abspath, lockers, 32, g_deep && r->is_dir);
#ifdef __linux__
    if (n <= 0) n = proc_scan(abspath, lockers, 32, r->is_dir);
#endif

    printf("\n[2] 占用进程\n");
    if (n > 0) {
        r->lockers = n;
        r->restricted = 1;
        printf("    %-8s %-28s %s\n", "PID", "进程名", "备注");
        printf("    %-8s %-28s %s\n", "--------", "----------------------------", "----------------");
        for (int i = 0; i < n; i++) {
            printf("    %-8ld %-28s %s\n", lockers[i].pid,
                   lockers[i].name[0] ? lockers[i].name : "(未知)",
                   lockers[i].detail[0] ? lockers[i].detail : "-");
            add_reason(r, "被进程占用：%s (PID %ld)", lockers[i].name[0] ? lockers[i].name : "(未知)", lockers[i].pid);
        }
        if (g_kill) {
            printf("\n    -- 正在结束占用进程 (-k) --\n");
            for (int i = 0; i < n; i++) posix_kill_pid(lockers[i].pid);
            usleep(500000);
            printf("    复测：%s\n", access(path, F_OK) == 0 ? "已发送信号，请重试删除操作" : "文件状态已变化");
            add_fix(r, "已向 %d 个进程发送 SIGTERM；若占用仍在，可试 kill -9 或重启", n);
        } else {
            add_fix(r, "确认无用后：kill %ld   或   filelock -k \"%s\"", lockers[0].pid, path);
            add_fix(r, "查看完整占用详情：lsof -- \"%s\"   /   lsof +D \"%s\"", abspath, abspath);
        }
    } else if (n == 0) {
        printf("    未发现持有该文件的用户态进程。\n");
        if (r->restricted)
            add_reason(r, "未发现用户态进程占用，可能是：内核态持有（挂载点/交换文件/NFS 租约）、僵尸句柄或权限不足看不到其他用户进程");
        add_fix(r, "macOS/Linux：sudo lsof -- \"%s\"  以 root 重扫", abspath);
    } else {
        printf("    扫描失败（缺少 lsof 且无 /proc 权限）\n");
        add_fix(r, "安装 lsof：macOS 自带；Debian/Ubuntu: sudo apt install lsof");
    }

    if (r->is_dir) {
        add_fix(r, "目录删除失败常见原因：① 目录内还有文件被打开 ② 目录本身是某进程的工作目录(cwd) ③ 存在挂载点");
        add_fix(r, "检查挂载点：mount | grep \"%s\"  （若被挂载，先 umount）", abspath);
    }
    if (r->restricted && r->is_link)
        add_fix(r, "注意这是符号链接：删除请用 rm \"%s\"（不带结尾斜杠），否则会操作到目标目录", path);
}

#endif /* !_WIN32 */

/* ================= 报告输出 ================= */

static void print_report(const char *path, Report *r)
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
        printf("    类型 : %s%s\n", r->is_dir ? "目录" : "文件", r->is_link ? "（符号链接/联接点）" : "");
        if (!r->is_dir) printf("    大小 : %lld %s\n", sz, unit);
        printf("    权限 : 读[%s]  写[%s]  删除/改名[%s]\n",
               r->can_read ? "✓" : "✗", r->can_write ? "✓" : "✗", r->can_delete ? "✓" : "✗");
    }

    printf("\n[3] 原因分析\n");
    if (r->nreasons == 0) {
        printf("    未发现明显问题，文件当前可以正常读写删除。\n");
    } else {
        for (int i = 0; i < r->nreasons; i++) printf("    %d) %s\n", i + 1, r->reasons[i]);
    }

    printf("\n[4] 解决办法\n");
    if (r->nfixes == 0) {
        printf("    无需处理。\n");
    } else {
        for (int i = 0; i < r->nfixes; i++) printf("    %d) %s\n", i + 1, r->fixes[i]);
    }

    printf("\n[5] 结论\n");
    if (!r->exists) printf("    路径不存在。\n");
    else if (r->lockers > 0) printf("    ✔ 找到 %d 个占用进程 —— 关闭它们（或用 -k）即可解除占用。\n", r->lockers);
    else if (r->restricted) printf("    ✔ 找到受限原因（见上），按建议逐条处理。\n");
    else printf("    ✔ 该路径当前没有被占用。\n");
    printf("========================================================\n");
}

static void usage(const char *prog)
{
    printf("filelock — 文件占用诊断工具 (Windows / macOS / Linux)\n\n");
    printf("用法: %s [选项] <文件或目录路径>\n\n", prog);
    printf("选项:\n");
    printf("  -v    详细模式（显示原始错误码与系统信息）\n");
    printf("  -k    结束占用进程后再复测（危险：会强制关闭程序）\n");
    printf("  -d    对目录递归扫描其中被打开的文件（lsof +D，可能较慢）\n");
    printf("  -h    显示本帮助\n\n");
    printf("退出码: 0=无占用  1=发现占用/受限  2=路径不存在  3=参数错误  4=系统调用失败\n");
    printf("示例:\n");
    printf("  %s C:\\\\temp\\\\report.xlsx\n", prog);
    printf("  %s ~/Documents/无法删除的文件夹\n", prog);
    printf("  %s -k /tmp/被占用.log\n", prog);
}

int main(int argc, char **argv)
{
    const char *path = NULL;

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] == '-' && a[1]) {
            for (const char *p = a + 1; *p; p++) {
                switch (*p) {
                case 'v': g_verbose = 1; break;
                case 'k': g_kill = 1; break;
                case 'd': g_deep = 1; break;
                case 'h': usage(argv[0]); return 0;
                default:
                    fprintf(stderr, "未知选项: -%c\n", *p);
                    usage(argv[0]);
                    return 3;
                }
            }
        } else {
            if (path) {
                fprintf(stderr, "只能指定一个路径。\n");
                return 3;
            }
            path = a;
        }
    }

    if (!path) {
        usage(argv[0]);
        return 3;
    }

    Report r;
    memset(&r, 0, sizeof(r));

    printf("正在诊断: %s\n", path);
    if (g_verbose) {
#ifdef _WIN32
        printf("(详细) 平台=Windows  选项: kill=%d  deep=%d\n", g_kill, g_deep);
        printf("(详细) 工作目录=");
        char cwd[2048];
        if (GetCurrentDirectoryA(sizeof(cwd), cwd)) printf("%s\n", cwd); else printf("(未知)\n");
#else
        printf("(详细) 平台=%s  pid=%d  选项: kill=%d  deep=%d\n",
#ifdef __APPLE__
               "macOS",
#elif defined(__linux__)
               "Linux",
#else
               "POSIX",
#endif
               (int)getpid(), g_kill, g_deep);
#endif
    }

#ifdef _WIN32
    diag_windows(path, &r);
#else
    diag_posix(path, &r);
#endif

    print_report(path, &r);

    if (!r.exists) return 2;
    if (r.lockers > 0 || r.restricted) return 1;
    return 0;
}
