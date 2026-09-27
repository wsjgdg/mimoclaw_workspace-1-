/*
 * main.c — 入口
 *   双击/无参数      → 启动图形界面（内置本地服务 + 自动打开浏览器）
 *   filelock 路径    → 命令行诊断（结果打印到终端）
 */
#include "filelock.h"

#ifdef _MSC_VER
#  pragma comment(lib, "comdlg32.lib")
#  pragma comment(lib, "shell32.lib")
#  pragma comment(lib, "ole32.lib")
#endif

static void get_exe_dir(char *out, size_t n)
{
    out[0] = 0;
#ifdef _WIN32
    char buf[4096];
    DWORD len = GetModuleFileNameA(NULL, buf, sizeof(buf));
    if (len > 0 && len < sizeof(buf)) {
        snprintf(out, n, "%s", buf);
        char *slash = strrchr(out, '\\');
        if (slash) *slash = 0;
    }
#elif defined(__linux__)
    char buf[4096];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = 0;
        snprintf(out, n, "%s", buf);
        char *slash = strrchr(out, '/');
        if (slash) *slash = 0;
    }
#elif defined(__APPLE__)
    char buf[4096];
    uint32_t sz = sizeof(buf);
    extern int _NSGetExecutablePath(char *, uint32_t *);
    if (_NSGetExecutablePath(buf, &sz) == 0) {
        char real[4096];
        if (realpath(buf, real)) snprintf(out, n, "%s", real);
        else snprintf(out, n, "%s", buf);
        char *slash = strrchr(out, '/');
        if (slash) *slash = 0;
    }
#endif
}

static int find_webroot(char *out, size_t n)
{
    char exe[4096];
    get_exe_dir(exe, sizeof(exe));
    const char *fmt[] = {
        "web",
        "%.4000s/web",
        "%.4000s/../web",
        "%.4000s/../share/filelock/web",
        "filelock/web",
        NULL
    };
    for (int i = 0; fmt[i]; i++) {
        char cand[8300], idx[8400];
        if (strchr(fmt[i], '%')) snprintf(cand, sizeof(cand), fmt[i], exe);
        else snprintf(cand, sizeof(cand), "%s", fmt[i]);
        snprintf(idx, sizeof(idx), "%s/index.html", cand);
        FILE *f = fopen(idx, "rb");
        if (f) { fclose(f); snprintf(out, n, "%.*s", (int)(n - 1), cand); return 0; }
    }
    return -1;
}

static void usage(const char *prog)
{
    printf("filelock — 文件占用诊断器（图形界面 + 命令行）\n\n");
    printf("用法:\n");
    printf("  %s                     启动图形界面（自动打开浏览器）\n", prog);
    printf("  %s <文件或目录路径>     命令行模式：诊断该路径\n", prog);
    printf("  %s --paste \"提示文本\"  命令行模式：分析报错提示，给出对策\n", prog);
    printf("\n选项:\n");
    printf("  -p <端口>     图形界面服务端口（默认 8632，被占用自动顺延）\n");
    printf("  --no-open     启动服务但不自动打开浏览器\n");
    printf("  --webroot 目录  指定 web 界面文件目录（默认自动查找 ./web）\n");
    printf("  -k            命令行模式：强制结束占用进程\n");
    printf("  -d            命令行模式：目录递归扫描（lsof +D，较慢）\n");
    printf("  --json        命令行模式：以 JSON 输出结果（便于脚本处理）\n");
    printf("  --wait <秒>   命令行模式：轮询等待直到文件解除占用\n");
    printf("  --install-menu    注册资源管理器右键菜单（Windows）\n");
    printf("  --uninstall-menu  移除右键菜单\n");
    printf("  -h            显示帮助\n");
}

static void print_report_json(const char *path, const Report *r)
{
    char esc[ITEM_LEN * 2], out[32768];
    size_t o = (size_t)snprintf(out, sizeof(out),
        "{\"path\":\"%s\",\"exists\":%d,\"isDir\":%d,\"canRead\":%d,"
        "\"canWrite\":%d,\"canDelete\":%d,",
        (json_escape(path, esc, sizeof(esc)), esc),
        r->exists, r->is_dir, r->can_read, r->can_write, r->can_delete);
    o += (size_t)snprintf(out + o, sizeof(out) - o, "\"lockers\":[");
    for (int i = 0; i < r->nlockers && o + 600 < sizeof(out); i++) {
        char e1[256];
        json_escape(r->lockers[i].name, e1, sizeof(e1));
        o += (size_t)snprintf(out + o, sizeof(out) - o,
            "%s{\"pid\":%ld,\"name\":\"%s\"}", i ? "," : "", r->lockers[i].pid, e1);
    }
    o += (size_t)snprintf(out + o, sizeof(out) - o, "],\"reasons\":[");
    for (int i = 0; i < r->nreasons && o + 600 < sizeof(out); i++) {
        json_escape(r->reasons[i], esc, sizeof(esc));
        o += (size_t)snprintf(out + o, sizeof(out) - o, "%s\"%s\"", i ? "," : "", esc);
    }
    o += (size_t)snprintf(out + o, sizeof(out) - o, "],\"fixes\":[");
    for (int i = 0; i < r->nfixes && o + 600 < sizeof(out); i++) {
        json_escape(r->fixes[i], esc, sizeof(esc));
        o += (size_t)snprintf(out + o, sizeof(out) - o, "%s\"%s\"", i ? "," : "", esc);
    }
    snprintf(out + o, sizeof(out) - o, "]}");
    printf("%s\n", out);
}

int main(int argc, char **argv)
{
    const char *path = NULL;
    const char *paste = NULL;
    const char *webroot_arg = NULL;
    int port = 8632, do_kill = 0, deep = 0, no_open = 0, json_out = 0, wait_sec = 0;

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-p") == 0 && i + 1 < argc) { port = atoi(argv[++i]); continue; }
        if (strcmp(a, "--webroot") == 0 && i + 1 < argc) { webroot_arg = argv[++i]; continue; }
        if (strcmp(a, "--no-open") == 0) { no_open = 1; continue; }
        if (strcmp(a, "--paste") == 0 && i + 1 < argc) { paste = argv[++i]; continue; }
        if (strcmp(a, "--json") == 0) { json_out = 1; continue; }
        if (strcmp(a, "--wait") == 0 && i + 1 < argc) { wait_sec = atoi(argv[++i]); continue; }
        if (strcmp(a, "--install-menu") == 0 || strcmp(a, "--uninstall-menu") == 0) {
            char err[512] = "";
            int ok = strcmp(a, "--install-menu") == 0 ?
                     install_context_menu(err, sizeof(err)) : uninstall_context_menu(err, sizeof(err));
            if (ok) printf("✔ 操作成功：%s\n", strcmp(a, "--install-menu") == 0 ?
                           "右键菜单已注册（在资源管理器中右键文件即可看到）" : "右键菜单已移除");
            else printf("✘ %s\n", err);
            return ok ? 0 : 4;
        }
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(argv[0]); return 0; }
        if (strcmp(a, "-k") == 0) { do_kill = 1; continue; }
        if (strcmp(a, "-d") == 0) { deep = 1; continue; }
        if (a[0] == '-' && a[1]) { fprintf(stderr, "未知选项: %s\n", a); usage(argv[0]); return 3; }
        if (path) { fprintf(stderr, "只能指定一个路径。\n"); return 3; }
        path = a;
    }

    /* ---- 粘贴提示分析（命令行） ---- */
    if (paste) {
        RuleHit hits[16];
        int n = analyze_text(paste, hits, 16);
        char paths[8][ITEM_LEN];
        int np = extract_paths(paste, paths, 8);
        if (n == 0) {
            printf("未匹配到已知规则。请把完整报错文本发给开发者补充规则库。\n");
            return 1;
        }
        printf("\n================ 报错提示分析 ================\n");
        for (int i = 0; i < n; i++) {
            printf("\n[%d] 原因：%s", i + 1, hits[i].cause);
            if (hits[i].platform == 1) printf("  (Windows)");
            if (hits[i].platform == 2) printf("  (macOS)");
            printf("\n    对策：\n");
            for (int f = 0; f < hits[i].nfixes; f++) printf("      %d) %s\n", f + 1, hits[i].fixes[f]);
        }
        if (np > 0) {
            printf("\n提示中检测到路径，可进一步用本工具检测占用进程：\n");
            for (int i = 0; i < np; i++) printf("      filelock \"%s\"\n", paths[i]);
        }
        printf("==============================================\n");
        return 0;
    }

    /* ---- 路径诊断（命令行） ---- */
    if (path) {
        Report r;
        diagnose_path(path, &r, deep);
        if (do_kill && r.nlockers > 0) {
            printf("正在结束 %d 个占用进程...\n", r.nlockers);
            for (int i = 0; i < r.nlockers; i++) {
                if (kill_locker(&r.lockers[i]) == 0) printf("  ✓ 已结束 PID %ld (%s)\n", r.lockers[i].pid, r.lockers[i].name);
                else printf("  ✗ 结束 PID %ld 失败（权限不足？）\n", r.lockers[i].pid);
            }
#ifdef _WIN32
            Sleep(800);
#else
            usleep(500000);
#endif
            diagnose_path(path, &r, deep);
        }
        if (wait_sec > 0) {
            int waited = 0;
            while (r.nlockers > 0 && waited < wait_sec) {
                if (!json_out) printf("[%d/%d] 仍被 %d 个进程占用，等待释放...\n", waited + 1, wait_sec, r.nlockers);
#ifdef _WIN32
                Sleep(1000);
#else
                sleep(1);
#endif
                waited++;
                diagnose_path(path, &r, deep);
            }
        }
        if (json_out) {
            print_report_json(path, &r);
        } else {
            print_report(path, &r);
        }
        return r.nlockers > 0 || r.restricted ? 1 : 0;
    }

    /* ---- 图形界面模式 ---- */
    char webroot[4096];
    if (webroot_arg) snprintf(webroot, sizeof(webroot), "%s", webroot_arg);
    else if (find_webroot(webroot, sizeof(webroot)) != 0) {
        webroot[0] = 0;   /* 使用内嵌界面（单文件模式） */
    }

    int realport = port;
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  filelock — 文件占用诊断器                   ║\n");
    printf("╚══════════════════════════════════════════════╝\n");
    printf("  界面来源 : %s\n", webroot[0] ? webroot : "内嵌（单文件模式）");
    printf("  服务地址 : http://127.0.0.1:%d/  （若端口被占用会自动顺延）\n", realport);
    printf("  （按 Ctrl+C 退出）\n\n");

    if (httpd_serve(webroot, &realport, no_open ? NULL : httpd_open_browser) != 0) {
        fprintf(stderr, "服务启动失败（端口 %d 不可用）。\n", realport);
        return 4;
    }
    return 0;
}
