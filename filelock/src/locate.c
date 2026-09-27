/*
 * locate.c — 按文件名在常见目录中定位真实路径（用于拖拽文件后自动找路径）
 * 直接扫描目录（不经过 shell），深度受限、结果数受限。
 */
#include "filelock.h"

#define MAX_DEPTH 5
#define MAX_FOUND 8

static int name_match(const char *a, const char *b)
{
#ifdef _WIN32
    return _stricmp(a, b) == 0;
#else
    return strcasecmp(a, b) == 0;
#endif
}

static int already_have(char out[][ITEM_LEN], int count, const char *path)
{
    for (int i = 0; i < count; i++)
        if (strcmp(out[i], path) == 0) return 1;
    return 0;
}

#ifdef _WIN32

static void scan_dir(const WCHAR *wdir, const char *name, char out[][ITEM_LEN],
                     int *count, int max, int depth)
{
    if (*count >= max || depth < 0) return;
    WCHAR pattern[3400];
    _snwprintf(pattern, 3400, L"%s\\*", wdir);

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        WCHAR wpath[3400];
        _snwprintf(wpath, 3400, L"%s\\%s", wdir, fd.cFileName);

        char fname[512], fpath[4096];
        WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, fname, sizeof(fname), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, wpath, -1, fpath, sizeof(fpath), NULL, NULL);

        if (name_match(fname, name) && *count < max && !already_have(out, *count, fpath)) {
            snprintf(out[*count], ITEM_LEN, "%.*s", ITEM_LEN - 1, fpath);
            (*count)++;
        }
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            scan_dir(wpath, name, out, count, max, depth - 1);
    } while (*count < max && FindNextFileW(h, &fd));
    FindClose(h);
}

static void root_dirs(char roots[][4096], int *nroots)
{
    char home[2048] = "";
    DWORD len = GetEnvironmentVariableA("USERPROFILE", home, sizeof(home));
    if (len == 0 || len >= sizeof(home)) snprintf(home, sizeof(home), "C:\\Users");
    const char *subs[] = { "", "\\Desktop", "\\Downloads", "\\Documents", NULL };
    *nroots = 0;
    for (int i = 0; subs[i]; i++) {
        snprintf(roots[*nroots], 4096, "%s%s", home, subs[i]);
        (*nroots)++;
    }
}

#else

#include <dirent.h>

static void scan_dir(const char *dir, const char *name, char out[][ITEM_LEN],
                     int *count, int max, int depth)
{
    if (*count >= max || depth < 0) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && *count < max) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char fpath[4096];
        snprintf(fpath, sizeof(fpath), "%.2000s/%.2000s", dir, de->d_name);

        struct stat st;
        if (lstat(fpath, &st) != 0) continue;

        if (name_match(de->d_name, name) && *count < max && !already_have(out, *count, fpath)) {
            snprintf(out[*count], ITEM_LEN, "%.*s", ITEM_LEN - 1, fpath);
            (*count)++;
        }
        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode))
            scan_dir(fpath, name, out, count, max, depth - 1);
    }
    closedir(d);
}

static void root_dirs(char roots[][4096], int *nroots)
{
    char home[2048] = "";
    const char *h = getenv("HOME");
    if (h) snprintf(home, sizeof(home), "%s", h);
    else snprintf(home, sizeof(home), "/home");
    const char *subs[] = { "", "/Desktop", "/Downloads", "/Documents", NULL };
    *nroots = 0;
    for (int i = 0; subs[i]; i++) {
        snprintf(roots[*nroots], 4096, "%s%s", home, subs[i]);
        (*nroots)++;
    }
}

#endif

int locate_path(const char *name, char out[][ITEM_LEN], int max)
{
    if (!name || !name[0]) return 0;
    /* 拒绝包含路径分隔符的名字，只接受纯文件名 */
    if (strchr(name, '/') || strchr(name, '\\') || strstr(name, "..")) return 0;

    int count = 0;
    char roots[8][4096];
    int nroots = 0;
    root_dirs(roots, &nroots);

    for (int i = 0; i < nroots && count < max; i++) {
#ifdef _WIN32
        WCHAR wroot[4096];
        MultiByteToWideChar(CP_UTF8, 0, roots[i], -1, wroot, 4096);
        scan_dir(wroot, name, out, &count, max, MAX_DEPTH);
#else
        scan_dir(roots[i], name, out, &count, max, MAX_DEPTH);
#endif
    }

    /* 当前目录附近 */
    char cwd[4096];
#ifdef _WIN32
    if (GetCurrentDirectoryA(sizeof(cwd), cwd) && count < max) {
        WCHAR wcwd[4096];
        MultiByteToWideChar(CP_UTF8, 0, cwd, -1, wcwd, 4096);
        scan_dir(wcwd, name, out, &count, max, 3);
    }
#else
    if (getcwd(cwd, sizeof(cwd)) && count < max)
        scan_dir(cwd, name, out, &count, max, 3);
#endif
    return count;
}
