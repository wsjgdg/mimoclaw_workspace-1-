/* 验证 macOS Finder 快速操作安装器生成的 plist 是否合法
 * 做法：用 -D__APPLE__ 在 Linux 上编译 src/menu.c 的 Apple 分支，
 * 调用 install_context_menu() 真实写出服务包，再用 python 的 plistlib 解析校验。 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

int install_context_menu(char *err, size_t ne);
int uninstall_context_menu(char *err, size_t ne);

/* menu.c 里 extern 声明了它，这里给个假实现 */
int _NSGetExecutablePath(char *b, uint32_t *s)
{
    const char *fake = "/fake/dir/filelock with space & <tag>";
    snprintf(b, *s, "%s", fake);
    *s = (uint32_t)strlen(b);
    return 0;
}

int main(void)
{
    char err[1024] = "";
    int ok = install_context_menu(err, sizeof(err));
    printf("install=%d err=%s\n", ok, err);
    return ok ? 0 : 1;
}
