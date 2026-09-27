/*
 * menu.c — 资源管理器右键菜单集成（Windows）
 *   filelock --install-menu    注册右键菜单「用 filelock 查占用」
 *   filelock --uninstall-menu  移除右键菜单
 *   写入 HKCU（当前用户），不需要管理员。
 *   macOS/Linux 提示使用系统自带方式（README 有说明）。
 */
#include "filelock.h"

#ifdef _WIN32

static int set_reg_sz(HKEY root, const char *subkey, const char *value_name,
                      const char *data, char *err, size_t ne)
{
    HKEY h;
    LONG rc = RegCreateKeyExA(root, subkey, 0, NULL, 0, KEY_WRITE, NULL, &h, NULL);
    if (rc != ERROR_SUCCESS) { snprintf(err, ne, "创建注册表项失败（错误 %ld）", (long)rc); return 0; }
    rc = RegSetValueExA(h, value_name, 0, REG_SZ, (const BYTE *)data, (DWORD)(strlen(data) + 1));
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS) { snprintf(err, ne, "写入注册表失败（错误 %ld）", (long)rc); return 0; }
    return 1;
}

static void del_reg_tree(HKEY root, const char *subkey)
{
    RegDeleteTreeA(root, subkey);
}

int install_context_menu(char *err, size_t ne)
{
    char exe[4096] = "";
    DWORD len = GetModuleFileNameA(NULL, exe, sizeof(exe));
    if (len == 0 || len >= sizeof(exe)) { snprintf(err, ne, "无法获取程序路径"); return 0; }

    char cmd[4200];
    snprintf(cmd, sizeof(cmd), "\"%s\" \"%%1\"", exe);

    /* 所有文件 */
    if (!set_reg_sz(HKEY_CURRENT_USER, "Software\\Classes\\*\\shell\\filelock", NULL,
                    "用 filelock 查占用（原因+对策）", err, ne)) return 0;
    if (!set_reg_sz(HKEY_CURRENT_USER, "Software\\Classes\\*\\shell\\filelock", "Icon", exe, err, ne)) return 0;
    if (!set_reg_sz(HKEY_CURRENT_USER, "Software\\Classes\\*\\shell\\filelock\\command", NULL, cmd, err, ne)) return 0;

    /* 文件夹 */
    if (!set_reg_sz(HKEY_CURRENT_USER, "Software\\Classes\\Directory\\shell\\filelock", NULL,
                    "用 filelock 查占用（原因+对策）", err, ne)) return 0;
    if (!set_reg_sz(HKEY_CURRENT_USER, "Software\\Classes\\Directory\\shell\\filelock", "Icon", exe, err, ne)) return 0;
    if (!set_reg_sz(HKEY_CURRENT_USER, "Software\\Classes\\Directory\\shell\\filelock\\command", NULL, cmd, err, ne)) return 0;

    /* 文件夹背景 */
    if (!set_reg_sz(HKEY_CURRENT_USER, "Software\\Classes\\Directory\\Background\\shell\\filelock", NULL,
                    "用 filelock 查占用（原因+对策）", err, ne)) return 0;
    if (!set_reg_sz(HKEY_CURRENT_USER, "Software\\Classes\\Directory\\Background\\shell\\filelock\\command", NULL,
                    cmd, err, ne)) return 0;
    return 1;
}

int uninstall_context_menu(char *err, size_t ne)
{
    (void)err; (void)ne;
    del_reg_tree(HKEY_CURRENT_USER, "Software\\Classes\\*\\shell\\filelock");
    del_reg_tree(HKEY_CURRENT_USER, "Software\\Classes\\Directory\\shell\\filelock");
    del_reg_tree(HKEY_CURRENT_USER, "Software\\Classes\\Directory\\Background\\shell\\filelock");
    return 1;
}

#else

int install_context_menu(char *err, size_t ne)
{
    snprintf(err, ne,
             "当前系统不支持自动注册右键菜单。\n"
             "  macOS：系统设置 → 键盘 → 快捷键 → 服务，或用“自动操作”创建快速操作（README 有步骤）\n"
             "  Linux：可自行创建 .desktop 文件放到 ~/.local/share/file-manager/actions/");
    return 0;
}

int uninstall_context_menu(char *err, size_t ne)
{
    snprintf(err, ne, "当前系统未注册右键菜单，无需移除");
    return 0;
}

#endif
