/*
 * browse.c — 原生文件/目录选择对话框
 *   Windows: GetOpenFileNameW / SHBrowseForFolderW
 *   macOS  : osascript (系统原生选择框)
 *   Linux  : zenity / kdialog（有则调用）
 */
#include "filelock.h"

#ifdef _WIN32

#include <commdlg.h>
#include <shlobj.h>

static void wide_to_utf8(const WCHAR *w, char *out, size_t n)
{
    int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (need <= 0) { snprintf(out, n, ""); return; }
    char *tmp = (char *)malloc((size_t)need);
    if (!tmp) { snprintf(out, n, ""); return; }
    WideCharToMultiByte(CP_UTF8, 0, w, -1, tmp, need, NULL, NULL);
    snprintf(out, n, "%s", tmp);
    free(tmp);
}

int native_browse(const char *type, char *path, size_t np, char *err, size_t ne)
{
    if (strcmp(type, "dir") == 0) {
        BROWSEINFOW bi;
        memset(&bi, 0, sizeof(bi));
        bi.lpszTitle = L"选择要诊断的文件夹";
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
        PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
        if (!pidl) { snprintf(err, ne, "已取消"); return -1; }
        WCHAR wdir[MAX_PATH * 2] = { 0 };
        if (!SHGetPathFromIDListW(pidl, wdir)) {
            CoTaskMemFree(pidl);
            snprintf(err, ne, "无法解析所选目录");
            return -1;
        }
        CoTaskMemFree(pidl);
        wide_to_utf8(wdir, path, np);
        return 0;
    }

    WCHAR wfile[32768] = { 0 };
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = wfile;
    ofn.nMaxFile = 32768;
    ofn.lpstrTitle = L"选择要诊断的文件";
    ofn.lpstrFilter = L"所有文件 (*.*)\0*.*\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn)) {
        snprintf(err, ne, "已取消");
        return -1;
    }
    wide_to_utf8(wfile, path, np);
    return 0;
}

#else

static int run_cmd_capture(const char *cmd, char *out, size_t n)
{
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    size_t got = fread(out, 1, n - 1, fp);
    out[got] = 0;
    int rc = pclose(fp);
    /* 去掉换行 */
    while (got && (out[got-1] == '\n' || out[got-1] == '\r')) out[--got] = 0;
    return rc == 0 ? 0 : -1;
}

int native_browse(const char *type, char *path, size_t np, char *err, size_t ne)
{
    char cmd[512];
    const char *is_dir = strcmp(type, "dir") == 0 ? "1" : "0";

#if defined(__APPLE__)
    if (strcmp(is_dir, "1") == 0)
        snprintf(cmd, sizeof(cmd),
                 "osascript -e 'POSIX path of (choose folder with prompt \"选择要诊断的文件夹\")' 2>/dev/null");
    else
        snprintf(cmd, sizeof(cmd),
                 "osascript -e 'POSIX path of (choose file with prompt \"选择要诊断的文件\")' 2>/dev/null");
    if (run_cmd_capture(cmd, path, np) == 0 && path[0]) return 0;
    snprintf(err, ne, "已取消或系统对话框不可用");
    return -1;
#else
    /* Linux：尝试 zenity / kdialog */
    if (system("command -v zenity >/dev/null 2>&1") == 0) {
        if (strcmp(is_dir, "1") == 0)
            snprintf(cmd, sizeof(cmd), "zenity --file-selection --directory --title='选择要诊断的文件夹' 2>/dev/null");
        else
            snprintf(cmd, sizeof(cmd), "zenity --file-selection --title='选择要诊断的文件' 2>/dev/null");
        if (run_cmd_capture(cmd, path, np) == 0 && path[0]) return 0;
        snprintf(err, ne, "已取消");
        return -1;
    }
    if (system("command -v kdialog >/dev/null 2>&1") == 0) {
        if (strcmp(is_dir, "1") == 0)
            snprintf(cmd, sizeof(cmd), "kdialog --getexistingdirectory / 2>/dev/null");
        else
            snprintf(cmd, sizeof(cmd), "kdialog --getopenfilename / 2>/dev/null");
        if (run_cmd_capture(cmd, path, np) == 0 && path[0]) return 0;
        snprintf(err, ne, "已取消");
        return -1;
    }
    snprintf(err, ne, "当前环境无图形对话框（未找到 zenity/kdialog），请手动输入路径");
    return -1;
#endif
}

#endif
