/*
 * tools/embed_web.c — 把 web 界面文件打包成 C 数组（构建时使用）
 *   用法: embed_web <输出.h> <数组名1> <文件1> [<数组名2> <文件2> ...]
 *   生成的头文件由 httpd.c 用作内置界面（找不到 web 目录时的兜底）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int emit(FILE *out, const char *name, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "embed_web: 无法打开 %s\n", path);
        return -1;
    }
    fprintf(out, "static const unsigned char %s[] = {\n", name);
    int c, col = 0;
    long len = 0;
    while ((c = fgetc(f)) != EOF) {
        fprintf(out, "0x%02x,", c);
        len++;
        if (++col % 16 == 0) fprintf(out, "\n");
    }
    if (col % 16) fprintf(out, "\n");
    fprintf(out, "};\nstatic const unsigned int %s_LEN = %ld;\n\n", name, len);
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 4 || argc % 2 != 0) {
        fprintf(stderr, "用法: %s <输出.h> <数组名> <文件> [...]\n", argv[0]);
        return 1;
    }
    FILE *out = fopen(argv[1], "w");
    if (!out) {
        fprintf(stderr, "embed_web: 无法写 %s\n", argv[1]);
        return 1;
    }
    fprintf(out,
        "/* 由 tools/embed_web.c 自动生成，请勿手改 */\n"
        "#ifndef WEB_EMBEDDED_H\n#define WEB_EMBEDDED_H\n\n");
    for (int i = 2; i < argc; i += 2) {
        if (emit(out, argv[i], argv[i + 1]) != 0) {
            fclose(out);
            return 1;
        }
    }
    fprintf(out, "#endif /* WEB_EMBEDDED_H */\n");
    fclose(out);
    return 0;
}
