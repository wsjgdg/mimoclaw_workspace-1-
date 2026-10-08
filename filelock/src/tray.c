/*
 * tray.c — Windows 系统托盘常驻（filelock --tray）
 *   启动本地服务后把进程收进托盘，不占任务栏：
 *     · 左键单击 / 菜单「打开界面」→ 打开浏览器界面
 *     · 菜单「退出」→ 结束进程
 *   服务跑在工作线程，主线程跑窗口消息循环（托盘必须有消息循环）。
 *   其他平台无托盘概念，直接返回 -1，由 main 走普通前台模式。
 */
#include "filelock.h"

#ifdef _WIN32

#ifndef _WIN32_IE
#  define _WIN32_IE 0x0600      /* 必须在包含 shellapi.h 之前定义，否则 NOTIFYICONDATAW 字段不全 */
#endif
#include <shellapi.h>

#define WM_TRAY        (WM_APP + 1)
#define ID_TRAY_OPEN   1001
#define ID_TRAY_EXIT   1002
#define ID_TRAY_ICON   1

static NOTIFYICONDATAW g_nid;
static int  g_port;
static char g_webroot[4096];

static void tray_open_ui(void)
{
    httpd_open_browser(g_port);
}

/* 服务线程：阻塞式 HTTP 循环 */
static DWORD WINAPI tray_server_thread(LPVOID arg)
{
    (void)arg;
    int p = g_port;
    httpd_serve(g_webroot[0] ? g_webroot : NULL, &p, NULL);
    return 0;
}

static LRESULT CALLBACK tray_wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_TRAY:
        if (lp == WM_LBUTTONUP) {
            tray_open_ui();
        } else if (lp == WM_RBUTTONUP || lp == WM_CONTEXTMENU) {
            POINT pt;
            GetCursorPos(&pt);
            HMENU m = CreatePopupMenu();
            if (m) {
                AppendMenuW(m, MF_STRING, ID_TRAY_OPEN, L"打开界面(&O)");
                AppendMenuW(m, MF_SEPARATOR, 0, NULL);
                AppendMenuW(m, MF_STRING, ID_TRAY_EXIT, L"退出(&X)");
                SetForegroundWindow(hwnd);
                TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(m);
            }
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_TRAY_OPEN: tray_open_ui(); return 0;
        case ID_TRAY_EXIT: DestroyWindow(hwnd); return 0;
        }
        break;

    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int tray_serve(const char *webroot, int *port)
{
    snprintf(g_webroot, sizeof(g_webroot), "%s", webroot ? webroot : "");
    g_port = *port;

    HINSTANCE hi = GetModuleHandleW(NULL);
    WNDCLASSW wc;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = tray_wnd_proc;
    wc.hInstance     = hi;
    wc.lpszClassName = L"filelockTrayWnd";
    if (!RegisterClassW(&wc)) return -1;

    /* 只创建消息窗口，不显示 */
    HWND hwnd = CreateWindowW(L"filelockTrayWnd", L"filelock", 0,
                              0, 0, 0, 0, NULL, NULL, hi, NULL);
    if (!hwnd) return -1;

    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize           = sizeof(g_nid);
    g_nid.hWnd             = hwnd;
    g_nid.uID              = ID_TRAY_ICON;
    g_nid.uFlags           = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY;
    g_nid.hIcon            = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
    lstrcpynW(g_nid.szTip, L"filelock — 文件占用诊断器",
              (int)(sizeof(g_nid.szTip) / sizeof(g_nid.szTip[0])));
    if (!Shell_NotifyIconW(NIM_ADD, &g_nid)) {
        DestroyWindow(hwnd);
        return -1;
    }

    /* 服务放到工作线程，主线程跑消息循环 */
    HANDLE th = CreateThread(NULL, 0, tray_server_thread, NULL, 0, NULL);
    if (!th) {
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        DestroyWindow(hwnd);
        return -1;
    }
    CloseHandle(th);

    printf("  托盘已就绪：右键图标可打开界面或退出\n");
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

#else  /* POSIX */

int tray_serve(const char *webroot, int *port)
{
    (void)webroot; (void)port;
    return -1;   /* 无系统托盘，由 main 走普通前台模式 */
}

#endif
