/*
 * clipboard.c — 系统剪贴板读取（本地，只读文本）
 *   Windows: OpenClipboard / CF_UNICODETEXT
 *   macOS  : pbpaste
 *   Linux  : wl-paste / xclip / xsel（有则调用）
 */
#include "filelock.h"

#ifdef _WIN32

int clipboard_read(char *buf, size_t n)
{
    buf[0] = 0;
    if (!OpenClipboard(NULL)) return -1;
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (!h) { CloseClipboard(); return 0; }
    const WCHAR *w = (const WCHAR *)GlobalLock(h);
    if (!w) { CloseClipboard(); return 0; }
    int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (need > 0) {
        if ((size_t)need > n) need = (int)n;
        WideCharToMultiByte(CP_UTF8, 0, w, -1, buf, need, NULL, NULL);
        buf[n - 1] = 0;
    }
    GlobalUnlock(h);
    CloseClipboard();
    return buf[0] ? 1 : 0;
}

#else

static int run_capture(const char *cmd, char *buf, size_t n)
{
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    size_t got = fread(buf, 1, n - 1, fp);
    buf[got] = 0;
    pclose(fp);
    while (got && (buf[got-1] == '\n' || buf[got-1] == '\r')) buf[--got] = 0;
    return got > 0 ? 1 : 0;
}

int clipboard_read(char *buf, size_t n)
{
    buf[0] = 0;
#if defined(__APPLE__)
    return run_capture("pbpaste 2>/dev/null", buf, n);
#else
    if (system("command -v wl-paste >/dev/null 2>&1") == 0)
        return run_capture("wl-paste -n 2>/dev/null", buf, n);
    if (system("command -v xclip >/dev/null 2>&1") == 0)
        return run_capture("xclip -selection clipboard -o 2>/dev/null", buf, n);
    if (system("command -v xsel >/dev/null 2>&1") == 0)
        return run_capture("xsel --clipboard --output 2>/dev/null", buf, n);
    return -1;
#endif
}

#endif
