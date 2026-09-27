/*
 * close_handle.c — Windows 句柄级解锁（不杀进程，只释放占用句柄）
 *   原理与 Unlocker 相同：
 *     NtQuerySystemInformation(SystemExtendedHandleInformation) 枚举全系统句柄
 *     → DuplicateHandle 复制到本进程 → GetFinalPathNameByHandleW 比对路径
 *     → DuplicateHandle(DUPLICATE_CLOSE_SOURCE) 关闭源句柄
 *   需要管理员权限（会尝试启用 SeDebugPrivilege）。
 *   POSIX 平台暂不支持（返回 -1）。
 */
#include "filelock.h"

#ifdef _WIN32

#ifndef NT_SUCCESS
#  define NT_SUCCESS(s) (((LONG)(s)) >= 0)
#endif
#define SystemExtendedHandleInformation 64

typedef LONG NTSTATUS_FL;

typedef struct {
    PVOID      Object;
    ULONG_PTR  UniqueProcessId;
    ULONG_PTR  HandleValue;
    ULONG      GrantedAccess;
    USHORT     CreatorBackTraceIndex;
    USHORT     ObjectTypeIndex;
    ULONG      HandleAttributes;
    ULONG      Reserved;
} SYS_HANDLE_ENTRY;

typedef struct {
    ULONG_PTR  NumberOfHandles;
    ULONG_PTR  Reserved;
    SYS_HANDLE_ENTRY Handles[1];
} SYS_HANDLE_INFO;

typedef NTSTATUS_FL (NTAPI *PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS_FL (NTAPI *PFN_NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);

static void enable_debug_priv(void)
{
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    LUID luid;
    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(tok);
}

static void wcopy(WCHAR *dst, size_t n, const WCHAR *src)
{
    wcsncpy(dst, src, n - 1);
    dst[n - 1] = 0;
}

/* 路径比较：去 \\?\ 前缀、大小写不敏感；dir 模式允许前缀匹配 */
static int path_matches(const WCHAR *cur, const WCHAR *target, int is_dir)
{
    const WCHAR *c = cur, *t = target;
    if (wcsncmp(c, L"\\\\?\\", 4) == 0) c += 4;
    if (wcsncmp(t, L"\\\\?\\", 4) == 0) t += 4;
    if (_wcsicmp(c, t) == 0) return 1;
    if (is_dir) {
        size_t tl = wcslen(t);
        if (_wcsnicmp(c, t, tl) == 0 && (c[tl] == L'\\' || c[tl] == L'/')) return 1;
    }
    return 0;
}

static int add_hit(UnlockHit *hits, int n, int max, DWORD pid, const WCHAR *wname)
{
    for (int i = 0; i < n; i++)
        if (hits[i].pid == (long)pid) { hits[i].count++; return n; }
    if (n >= max) return n;
    hits[n].pid = (long)pid;
    hits[n].count = 1;
    WideCharToMultiByte(CP_UTF8, 0, wname ? wname : L"(未知)", -1,
                        hits[n].name, sizeof(hits[n].name), NULL, NULL);
    return n + 1;
}

int close_file_handles(const char *path, int is_dir, int *closed,
                       UnlockHit *hits, int maxhits, char *err, size_t ne)
{
    *closed = 0;
    enable_debug_priv();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) { snprintf(err, ne, "无法加载 ntdll"); return -1; }
    PFN_NtQuerySystemInformation NtQSI =
        (PFN_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    PFN_NtDuplicateObject NtDup =
        (PFN_NtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");
    if (!NtQSI || !NtDup) { snprintf(err, ne, "缺少系统接口"); return -1; }

    /* 目标路径规范化 */
    WCHAR wtarget[8192];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wtarget, 8192))
        MultiByteToWideChar(CP_ACP, 0, path, -1, wtarget, 8192);
    WCHAR wfull[8192];
    DWORD fl = GetFullPathNameW(wtarget, 8192, wfull, NULL);
    if (fl == 0 || fl >= 8192) wcopy(wfull, 8192, wtarget);

    /* 枚举全系统句柄（动态扩缓冲） */
    ULONG len = 16 * 1024 * 1024;
    SYS_HANDLE_INFO *info = NULL;
    NTSTATUS_FL st;
    for (;;) {
        info = (SYS_HANDLE_INFO *)realloc(info, len);
        if (!info) { snprintf(err, ne, "内存不足"); return -1; }
        ULONG need = 0;
        st = NtQSI(SystemExtendedHandleInformation, info, len, &need);
        if (NT_SUCCESS(st)) break;
        if (need > len) { len = need + 1024 * 1024; continue; }
        len *= 2;
        if (len > 512 * 1024 * 1024) { free(info); snprintf(err, ne, "句柄表过大（错误 %ld）", (long)st); return -1; }
    }

    DWORD self = GetCurrentProcessId();
    int nhits = 0;

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        SYS_HANDLE_ENTRY *e = &info->Handles[i];
        if ((DWORD)e->UniqueProcessId == self) continue;

        HANDLE hproc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)e->UniqueProcessId);
        if (!hproc) continue;

        HANDLE hcopy = NULL;
        if (!DuplicateHandle(hproc, (HANDLE)e->HandleValue, GetCurrentProcess(), &hcopy,
                             0, FALSE, DUPLICATE_SAME_ACCESS)) {
            CloseHandle(hproc);
            continue;
        }

        /* 只关心磁盘文件对象 */
        int matched = 0;
        if (GetFileType(hcopy) == FILE_TYPE_DISK) {
            WCHAR wcur[8192] = { 0 };
            DWORD n = GetFinalPathNameByHandleW(hcopy, wcur, 8192, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            if (n > 0 && n < 8192 && path_matches(wcur, wfull, is_dir)) matched = 1;
        }

        if (matched) {
            /* 关闭源句柄（进程不受影响，只是失去对该文件的句柄） */
            HANDLE dummy = NULL;
            if (NT_SUCCESS(NtDup(hproc, (HANDLE)e->HandleValue, NULL, &dummy, 0, 0, DUPLICATE_CLOSE_SOURCE))) {
                (*closed)++;
                WCHAR wname[128] = L"(未知)";
                WCHAR wexe[MAX_PATH * 2] = { 0 };
                HANDLE hq = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)e->UniqueProcessId);
                if (hq) {
                    DWORD sz = MAX_PATH * 2;
                    if (QueryFullProcessImageNameW(hq, 0, wexe, &sz)) {
                        WCHAR *slash = wcsrchr(wexe, L'\\');
                        wcopy(wname, 128, slash ? slash + 1 : wexe);
                    }
                    CloseHandle(hq);
                }
                nhits = add_hit(hits, nhits, maxhits, (DWORD)e->UniqueProcessId, wname);
            }
        }

        CloseHandle(hcopy);
        CloseHandle(hproc);
    }

    free(info);
    return 0;
}

#else  /* POSIX */

int close_file_handles(const char *path, int is_dir, int *closed,
                       UnlockHit *hits, int maxhits, char *err, size_t ne)
{
    (void)path; (void)is_dir; (void)hits; (void)maxhits;
    *closed = 0;
    snprintf(err, ne, "当前系统不支持句柄级解锁（仅 Windows）；macOS/Linux 请用 kill 结束占用进程");
    return -1;
}

#endif
