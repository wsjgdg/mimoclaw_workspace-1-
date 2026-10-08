/*
 * open.c — 一键打开图形界面并定位到指定路径（filelock --open [路径]）
 *   右键菜单（资源管理器 / Finder）用它：本地服务已在跑就直接用，
 *   没跑就先拉起一个脱离终端的后台进程，再打开浏览器并自动填好路径开始检测。
 *   这样右键菜单不需要弹命令行窗口，直接落到图形界面。
 */
#include "filelock.h"

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <sys/wait.h>
#endif

#define OPEN_PORT 8632

/* ---- 工具 ---- */

/* 自身可执行文件完整路径 */
static void self_exe(char *out, size_t n)
{
    out[0] = 0;
#ifdef _WIN32
    DWORD len = GetModuleFileNameA(NULL, out, (DWORD)n);
    if (len == 0 || len >= n) out[0] = 0;
#elif defined(__linux__)
    ssize_t len = readlink("/proc/self/exe", out, n - 1);
    if (len > 0) out[len] = 0; else out[0] = 0;
#elif defined(__APPLE__)
    char buf[4096], real[4096];
    uint32_t sz = sizeof(buf);
    extern int _NSGetExecutablePath(char *, uint32_t *);
    if (_NSGetExecutablePath(buf, &sz) == 0) {
        if (realpath(buf, real)) snprintf(out, n, "%s", real);
        else                     snprintf(out, n, "%s", buf);
    }
#endif
}

/* 查询字符串编码（保留 / : 便于阅读，其余非安全字符转 %XX） */
static void url_encode(const char *in, char *out, size_t n)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && o + 4 < n; p++) {
        unsigned char c = *p;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~' || c == '/' || c == ':') {
            out[o++] = (char)c;
        } else {
            out[o++] = '%';
            out[o++] = hex[c >> 4];
            out[o++] = hex[c & 15];
        }
    }
    out[o] = 0;
}

/* 端口是否有服务在监听（仅探本机回环） */
static int port_alive(int port)
{
#ifdef _WIN32
    static int wsainit = 0;
    if (!wsainit) {
        WSADATA w;
        if (WSAStartup(MAKEWORD(2, 2), &w) == 0) wsainit = 1;
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return 0;
#else
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
#endif
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    sa.sin_addr.s_addr = htonl(0x7f000001);          /* 127.0.0.1 */
    int ok = (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0);
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
    return ok;
}

/* 拉起一个脱离终端的后台服务进程：自己 + "--no-open" */
static int spawn_self_detached(char *err, size_t ne)
{
    char exe[4096] = "";
    self_exe(exe, sizeof(exe));
    if (!exe[0]) { snprintf(err, ne, "无法获取程序路径"); return -1; }

#ifdef _WIN32
    char cmd[4300];
    snprintf(cmd, sizeof(cmd), "\"%s\" --no-open -p %d", exe, OPEN_PORT);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                        NULL, NULL, &si, &pi)) {
        snprintf(err, ne, "启动后台服务失败（错误 %lu）", (unsigned long)GetLastError());
        return -1;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
#else
    pid_t pid = fork();
    if (pid < 0) { snprintf(err, ne, "fork 失败：%s", strerror(errno)); return -1; }
    if (pid == 0) {
        setsid();
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
            if (fd > 2) close(fd);
        }
        char portstr[16];
        snprintf(portstr, sizeof(portstr), "%d", OPEN_PORT);
        execl(exe, exe, "--no-open", "-p", portstr, (char *)NULL);
        _exit(127);
    }
    return 0;
#endif
}

/* ---- 对外接口 ---- */

int open_ui(const char *path, char *err, size_t ne)
{
    if (!port_alive(OPEN_PORT)) {
        if (spawn_self_detached(err, ne) != 0) return -1;
        /* 等服务就绪（最多约 4 秒） */
        for (int i = 0; i < 40 && !port_alive(OPEN_PORT); i++) {
#ifdef _WIN32
            Sleep(100);
#else
            usleep(100000);
#endif
        }
        if (!port_alive(OPEN_PORT)) {
            snprintf(err, ne, "后台服务启动失败（端口 %d 不可用？）", OPEN_PORT);
            return -1;
        }
    }

    char url[4600];
    if (path && path[0]) {
        char enc[4096];
        url_encode(path, enc, sizeof(enc));
        snprintf(url, sizeof(url), "http://127.0.0.1:%d/?path=%s", OPEN_PORT, enc);
    } else {
        snprintf(url, sizeof(url), "http://127.0.0.1:%d/", OPEN_PORT);
    }
    return httpd_open_url(url);
}
