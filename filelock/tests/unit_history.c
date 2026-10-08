/*
 * unit_history.c — 检测历史的单元测试（history.c）
 *   用临时 HOME 做隔离，不碰真实 ~/.filelock_history.jsonl。
 *   覆盖：写入→立即可读、倒序、分页、搜索、超量截断、清空、空文件。
 */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../src/filelock.h"

static int g_pass = 0, g_fail = 0;

static void check(int cond, const char *desc)
{
    if (cond) { g_pass++; printf("  \xe2\x9c\x94 %s\n", desc); }
    else      { g_fail++; printf("  \xe2\x9c\x98 %s\n", desc); }
}

static void add_n(int base, int count)
{
    Report r;
    memset(&r, 0, sizeof(r));
    r.exists = 1; r.can_read = 1; r.can_write = 1; r.can_delete = 1;
    for (int i = 0; i < count; i++) {
        char p[64];
        snprintf(p, sizeof(p), "/tmp/case%d.txt", base + i);
        history_add(p, &r);
    }
}

int main(void)
{
    /* 隔离 HOME：全部写到临时目录 */
    char dir[] = "/tmp/flhistXXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
    setenv("HOME", dir, 1);
    char hfile[512];
    snprintf(hfile, sizeof(hfile), "%s/.filelock_history.jsonl", dir);

    printf("== 写入与读取 ==\n");
    add_n(0, 5);
    HistoryItem items[64];
    long long total = 0;
    int n = history_page(items, 64, 0, 64, NULL, &total);
    check(total == 5, "写入 5 条后 total=5（缓冲已自动落盘）");
    check(n == 5, "一页返回 5 条");
    check(strcmp(items[0].path, "/tmp/case4.txt") == 0, "最新记录排在最前（倒序）");
    check(strcmp(items[4].path, "/tmp/case0.txt") == 0, "最旧记录排在最后");
    check(items[0].exists == 1 && items[0].conclusion[0], "字段解析完整");
    check(items[0].can_read == 1 && items[0].can_write == 1 && items[0].can_delete == 1,
          "读/写/删三态随历史留存（供“上次 vs 现在”对比）");

    printf("== 分页 ==\n");
    n = history_page(items, 64, 0, 2, NULL, &total);
    check(n == 2 && total == 5, "每页 2 条时首页 2 条、total 仍为 5");
    n = history_page(items, 64, 2, 2, NULL, &total);
    check(n == 1, "第 3 页只剩 1 条");
    n = history_page(items, 64, 9, 2, NULL, &total);
    check(n == 0, "越界页返回空");
    n = history_page(items, 64, 0, 9999, NULL, &total);
    check(n == 5, "per_page 超限会被钳制，不越界写");

    printf("== 搜索 ==\n");
    n = history_page(items, 64, 0, 64, "case2", &total);
    check(n == 1 && total == 1 && strcmp(items[0].path, "/tmp/case2.txt") == 0,
          "按路径搜到唯一一条");
    n = history_page(items, 64, 0, 64, "CASE2", &total);
    check(total == 1, "搜索大小写不敏感");
    n = history_page(items, 64, 0, 64, "\xe6\xb2\xa1\xe6\x9c\x89\xe8\xa2\xab\xe5\x8d\xa0\xe7\x94\xa8", &total);
    check(total == 5, "按结论文本也能搜（不只是路径）");
    n = history_page(items, 64, 0, 64, "zzz_no_such", &total);
    check(total == 0 && n == 0, "无命中返回 0 条");
    n = history_page(items, 64, 0, 64, "", &total);
    check(total == 5, "空搜索词等同于不筛选");

    printf("== 超量截断 ==\n");
    add_n(1000, 300);
    n = history_page(items, 1, 0, 1, NULL, &total);
    check(total > 0 && total <= 250, "超过 200 条后自动截断，不再无限增长");
    check(strcmp(items[0].path, "/tmp/case1299.txt") == 0, "截断保留了最新记录");
    {
        FILE *f = fopen(hfile, "r");
        int lines = 0;
        if (f) { char buf[2048]; while (fgets(buf, sizeof(buf), f)) lines++; fclose(f); }
        check(lines <= 250, "文件行数已收敛（不是只在内存里截断）");
    }

    printf("== 清空与边界 ==\n");
    check(history_clear() == 0, "清空成功");
    n = history_page(items, 64, 0, 64, NULL, &total);
    check(total == 0 && n == 0, "清空后查不到任何记录");
    add_n(2000, 1);
    n = history_page(items, 64, 0, 64, NULL, &total);
    check(total == 1 && strcmp(items[0].path, "/tmp/case2000.txt") == 0,
          "清空后仍可继续记录（缓冲状态已重置）");
    history_clear();
    n = history_page(items, 64, 0, 64, "whatever", NULL);
    check(n == 0, "文件不存在时搜索不崩、返回 0");
    check(history_list(items, 4) == 0, "history_list 空文件返回 0");

    /* 收拾现场 */
    remove(hfile);
    rmdir(dir);

    printf("\n== 结果: %d 通过 / %d 失败 ==\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
