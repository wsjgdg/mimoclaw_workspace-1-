/*
 * autostart.c — 开机自启注册（Windows / macOS / Linux）
 *   filelock --install-autostart    注册开机自启（登录后静默启动界面服务）
 *   filelock --uninstall-autostart  移除开机自启
 *   filelock --autostart-status     查看是否已注册
 *
 * 落点（都只影响当前用户，不需要管理员）：
 *   Windows: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
 *   macOS  : ~/Library/LaunchAgents/com.wsjgdg.filelock.plist
 *   Linux  : ~/.config/autostart/filelock.desktop
 * 启动参数统一用 --no-open：开机后台跑服务，不弹浏览器打扰用户，
 * 系统托盘或手动访问 http://127.0.0.1:8632/ 即可打开界面。
 */
#include "filelock.h"

#ifndef _WIN32
#  include <sys/stat.h>
#endif

#define AUTOSTART_NAME "filelock"
#define LAUNCH_ARGS    "--no-open"

/* 自身可执行文件完整路径（自启动项需要绝对路径） */
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
#else
    (void)out; (void)n;
#endif
}

#ifndef _WIN32
/* 逐级创建目录（类似 mkdir -p） */
static int mkdir_p(const char *dir, char *err, size_t ne)
{
    char tmp[4200];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                snprintf(err, ne, "创建目录 %.300s 失败：%.100s", tmp, strerror(errno));
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        snprintf(err, ne, "创建目录 %.300s 失败：%.100s", tmp, strerror(errno));
        return -1;
    }
    return 0;
}

static int write_text_file(const char *path, const char *text, char *err, size_t ne)
{
    FILE *f = fopen(path, "w");
    if (!f) { snprintf(err, ne, "写入 %.300s 失败：%.100s", path, strerror(errno)); return -1; }
    fputs(text, f);
    fclose(f);
    return 0;
}

/* 自启动项落点 */
static void autostart_path(char *out, size_t n)
{
    out[0] = 0;
    const char *home = getenv("HOME");
    if (!home || !home[0]) return;
#if defined(__APPLE__)
    snprintf(out, n, "%s/Library/LaunchAgents/com.wsjgdg.filelock.plist", home);
#else
    snprintf(out, n, "%s/.config/autostart/" AUTOSTART_NAME ".desktop", home);
#endif
}
#endif /* !_WIN32 */

int install_autostart(char *err, size_t ne)
{
    char exe[4096] = "";
    self_exe(exe, sizeof(exe));
    if (!exe[0]) { snprintf(err, ne, "无法获取程序路径"); return 0; }

#ifdef _WIN32
    char cmd[4300];
    snprintf(cmd, sizeof(cmd), "\"%s\" " LAUNCH_ARGS, exe);
    HKEY h;
    LONG rc = RegCreateKeyExA(HKEY_CURRENT_USER,
                              "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                              0, NULL, 0, KEY_WRITE, NULL, &h, NULL);
    if (rc != ERROR_SUCCESS) { snprintf(err, ne, "打开注册表 Run 项失败（错误 %ld）", (long)rc); return 0; }
    rc = RegSetValueExA(h, AUTOSTART_NAME, 0, REG_SZ,
                        (const BYTE *)cmd, (DWORD)(strlen(cmd) + 1));
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS) { snprintf(err, ne, "写入注册表失败（错误 %ld）", (long)rc); return 0; }
    return 1;
#else
    char dir[4200], path[4200];
    autostart_path(path, sizeof(path));
    if (!path[0]) { snprintf(err, ne, "找不到 HOME 目录"); return 0; }
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) *slash = 0;
    if (mkdir_p(dir, err, ne) != 0) return 0;

    char text[8192];
#if defined(__APPLE__)
    snprintf(text, sizeof(text),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n"
        "<dict>\n"
        "  <key>Label</key>\n"
        "  <string>com.wsjgdg.filelock</string>\n"
        "  <key>ProgramArguments</key>\n"
        "  <array>\n"
        "    <string>%s</string>\n"
        "    <string>" LAUNCH_ARGS "</string>\n"
        "  </array>\n"
        "  <key>RunAtLoad</key>\n"
        "  <true/>\n"
        "  <key>KeepAlive</key>\n"
        "  <false/>\n"
        "</dict>\n"
        "</plist>\n", exe);
#else
    snprintf(text, sizeof(text),
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Version=1.0\n"
        "Name=filelock 文件占用诊断器\n"
        "Comment=后台常驻，随时查文件被谁占用\n"
        "Exec=%s " LAUNCH_ARGS "\n"
        "Terminal=false\n"
        "X-GNOME-Autostart-enabled=true\n"
        "NoDisplay=true\n", exe);
#endif
    return write_text_file(path, text, err, ne) == 0;
#endif
}

int uninstall_autostart(char *err, size_t ne)
{
#ifdef _WIN32
    HKEY h;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER,
                            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            0, KEY_WRITE, &h);
    if (rc != ERROR_SUCCESS) return 1;   /* 连 Run 项都没有 = 本来就没注册 */
    rc = RegDeleteValueA(h, AUTOSTART_NAME);
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) {
        snprintf(err, ne, "删除注册表值失败（错误 %ld）", (long)rc);
        return 0;
    }
    return 1;
#else
    char path[4200];
    autostart_path(path, sizeof(path));
    if (!path[0]) { snprintf(err, ne, "找不到 HOME 目录"); return 0; }
    if (remove(path) != 0 && errno != ENOENT) {
        snprintf(err, ne, "删除 %.300s 失败：%.100s", path, strerror(errno));
        return 0;
    }
    return 1;
#endif
}

int autostart_installed(void)
{
#ifdef _WIN32
    HKEY h;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_QUERY_VALUE, &h) != ERROR_SUCCESS) return 0;
    DWORD type = 0, size = 0;
    LONG rc = RegQueryValueExA(h, AUTOSTART_NAME, NULL, &type, NULL, &size);
    RegCloseKey(h);
    return (rc == ERROR_SUCCESS && size > 0) ? 1 : 0;
#else
    char path[4200];
    autostart_path(path, sizeof(path));
    return (path[0] && access(path, F_OK) == 0) ? 1 : 0;
#endif
}
