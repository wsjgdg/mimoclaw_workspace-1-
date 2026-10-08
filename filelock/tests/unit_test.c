/*
 * unit_test.c — 规则库与 JSON 工具的单元测试
 *   构建/运行：make test
 *   只依赖 src/rules.c + src/jsonutil.c，不碰网络与文件系统，跑得飞快。
 */
#include "../src/filelock.h"

static int g_pass = 0, g_fail = 0;

static void check(int cond, const char *desc)
{
    if (cond) { g_pass++; printf("  \xe2\x9c\x94 %s\n", desc); }
    else      { g_fail++; printf("  \xe2\x9c\x98 %s\n", desc); }
}

static int contains(const char *hay, const char *needle)
{
    return hay && needle && strstr(hay, needle) != NULL;
}

/* ---------- 规则库：每类报错都应命中且给出对策 ---------- */

static void expect_rule(const char *text, const char *cause_kw, const char *desc)
{
    RuleHit hits[8];
    int n = analyze_text(text, hits, 8);
    /* 规则会按命中数排序并可能多条命中，只要期望的那条在结果里且带对策就算过 */
    int found = 0, rank = -1;
    for (int i = 0; i < n; i++)
        if (contains(hits[i].cause, cause_kw) && hits[i].nfixes > 0) { found = 1; rank = i; break; }
    if (!found)
        printf("      (实际 n=%d top=%s)\n", n, n > 0 ? hits[0].cause : "-");
    else if (rank > 0)
        printf("      (提示：该规则排在第 %d 位，首位是 %s)\n", rank + 1, hits[0].cause);
    check(found, desc);
}

static void test_rules(void)
{
    printf("== 规则库 ==\n");
    expect_rule("\xe5\x8f\xa6\xe4\xb8\x80\xe4\xb8\xaa\xe7\xa8\x8b\xe5\xba\x8f\xe6\xad\xa3\xe5\x9c\xa8\xe4\xbd\xbf\xe7\x94\xa8\xe6\xad\xa4\xe6\x96\x87\xe4\xbb\xb6",
                "\xe5\x8d\xa0\xe7\x94\xa8", "中文“另一个程序正在使用此文件”命中占用规则");
    expect_rule("The process cannot access the file because it is being used by another process",
                "\xe5\x8d\xa0\xe7\x94\xa8", "英文 being used by another process 命中占用规则");
    expect_rule("Access is denied", "\xe6\x9d\x83\xe9\x99\x90", "Access is denied 命中权限规则");
    expect_rule("Text file busy", "\xe7\x8b\xac\xe5\x8d\xa0", "Text file busy 命中独占规则");
    expect_rule("The disk is write-protected", "\xe5\x8f\xaa\xe8\xaf\xbb", "write-protected 命中只读规则");
    expect_rule("filename too long", "\xe8\xb7\xaf\xe5\xbe\x84", "filename too long 命中路径过长规则");
    expect_rule("The action cannot be completed because the folder is open in another program",
                "\xe8\xb5\x84\xe6\xba\x90\xe7\xae\xa1\xe7\x90\x86", "资源管理器占用提示命中");

    expect_rule("The requested operation cannot be performed on a file with a user-mapped section open",
                "\xe5\x86\x85\xe5\xad\x98\xe6\x98\xa0\xe5\xb0\x84", "user-mapped section 命中内存映射规则");
    expect_rule("The document is in use by another application",
                "Office", "Office 文档内部锁定命中规则");
    expect_rule("MacOS error -8003 while deleting",
                "macOS", "macOS 系统错误码命中规则");
    expect_rule("The file is temporarily unavailable, please try again later",
                "\xe7\xa8\x8d\xe5\x90\x8e", "稍后重试类临时占用命中规则");
    expect_rule("The network path was not found",
                "\xe7\xbd\x91\xe7\xbb\x9c", "网络路径不可达命中规则");
    expect_rule("too many levels of symbolic links",
                "\xe7\xac\xa6\xe5\x8f\xb7\xe9\x93\xbe\xe6\x8e\xa5", "符号链接异常命中规则");
    expect_rule("cannot create a file when that file already exists",
                "\xe5\x90\x8c\xe5\x90\x8d", "文件已存在命中规则");
    expect_rule("bash: open: Too many open files",
                "\xe5\x8f\xa5\xe6\x9f\x84", "句柄耗尽命中规则");

    /* 归一化容错：OCR / 跨行排版 / 全半角混杂粘过来的报错也要能命中 */
    expect_rule("The process cannot access the file because it is being used by\nanother\tprocess.",
                "\xe5\x8d\xa0\xe7\x94\xa8", "跨行断词/制表符不影响匹配");
    expect_rule("\xef\xbc\xa1\xef\xbc\xa3\xef\xbc\xa3\xef\xbd\x85\xef\xbd\x93\xef\xbd\x93\xe3\x80\x80\xef\xbd\x89\xef\xbd\x93\xe3\x80\x80\xef\xbd\x84\xef\xbd\x85\xef\xbd\x8e\xef\xbd\x89\xef\xbd\x85\xef\xbd\x84",
                "\xe6\x9d\x83\xe9\x99\x90", "全角字母 + 全角空格不影响匹配");
    expect_rule("being\xe2\x80\x8b used by\xe2\x80\x8c another process",
                "\xe5\x8d\xa0\xe7\x94\xa8", "零宽字符不影响匹配");
    /* 注：\x 后面会贪婪吃十六进制位，\xc2\xad 要写成 \xc2\xad" "，
     * 否则 \xc2ad 被当成同一个转义 */
    expect_rule("being used by anoth\xc2\xad" "er process",
                "\xe5\x8d\xa0\xe7\x94\xa8", "软连字符不影响匹配");
    expect_rule("０ｘ８００７００２０",
                "Windows \xe9\x94\x99\xe8\xaf\xaf\xe7\xa0\x81", "全角错误码归一化后命中");

    /* 未命中 / 边界 */
    RuleHit hits[8];
    check(analyze_text("", hits, 8) == 0, "空文本不命中任何规则");
    check(analyze_text("完全无关的一段话，只是随便写写", hits, 8) == 0, "无关文本不命中");
    check(analyze_text("readonly-ish but not a keyword", hits, 8) == 0, "非关键词不误报");

    /* 超长输入不应崩溃或溢出 */
    {
        static char big[200000];
        memset(big, 'a', sizeof(big) - 1);
        big[sizeof(big) - 1] = 0;
        memcpy(big, "Access is denied ", 17);
        int n = analyze_text(big, hits, 8);
        check(n > 0, "超长输入（200KB）仍能正常匹配且不崩溃");
    }

    /* max=0 / max 上限 */
    check(analyze_text("Access is denied", hits, 0) >= 0, "max=0 不越界");
    check(analyze_text("Access is denied", hits, 1) <= 1, "max=1 不超上限");
}

/* ---------- 路径提取 ---------- */

static void test_paths(void)
{
    printf("== 路径提取 ==\n");
    char out[8][ITEM_LEN];

    int n = extract_paths(
        "无法删除 C:\\Users\\test\\report.docx，另一程序正使用 /home/user/data/a.log",
        out, 8);
    int got_win = 0, got_posix = 0;
    for (int i = 0; i < n; i++) {
        if (contains(out[i], "report.docx")) got_win = 1;
        if (contains(out[i], "a.log")) got_posix = 1;
    }
    check(n >= 2, "一次提取出多个路径（不再一路吃到行尾）");
    check(got_win, "提取到 Windows 路径");
    check(got_posix, "提取到 POSIX 路径");

    /* 引号内的路径允许含空格 */
    n = extract_paths(
        "The file \"C:\\Program Files\\My App\\log.txt\" is in use.", out, 8);
    check(n == 1 && strcmp(out[0], "C:\\Program Files\\My App\\log.txt") == 0,
          "引号内的含空格路径完整提取");

    /* 中英文句子标点都应终止路径 */
    n = extract_paths("无法删除 C:\\a.txt；也无法删 /home/b.log。", out, 8);
    check(n == 2 && strcmp(out[0], "C:\\a.txt") == 0 && strcmp(out[1], "/home/b.log") == 0,
          "中英文标点都正确截断路径");

    check(extract_paths("没有任何路径的普通句子。", out, 8) == 0, "无路径返回 0");

    /* 超长输入 + 上限 */
    n = extract_paths("C:\\a.txt C:\\b.txt C:\\c.txt C:\\d.txt", out, 2);
    check(n == 2, "max=2 时只返回 2 个路径");
}

/* ---------- JSON 工具 ---------- */

static void test_json(void)
{
    printf("== JSON 工具 ==\n");
    char buf[512];

    json_escape("a\"b\\c\nd\te", buf, sizeof(buf));
    check(contains(buf, "\\\"") && contains(buf, "\\\\") &&
          contains(buf, "\\n") && contains(buf, "\\t"),
          "json_escape 转义引号/反斜杠/换行/制表符");

    json_escape("x\x01y", buf, sizeof(buf));
    check(contains(buf, "\\u0001"), "json_escape 把控制字符转成 \\uXXXX");

    /* 超长内容必须被安全截断且始终 NUL 结尾 */
    {
        static char big[4096], out2[64];
        memset(big, 'z', sizeof(big) - 1);
        big[sizeof(big) - 1] = 0;
        json_escape(big, out2, sizeof(out2));
        check(strlen(out2) < sizeof(out2), "json_escape 长内容安全截断");
    }

    const char *j = "{\"a\":123,\"s\":\"hi there\",\"n\":-7}";
    check(json_get_int(j, "a", -1) == 123, "json_get_int 读正整数");
    check(json_get_int(j, "n", 0) == -7, "json_get_int 读负整数");
    check(json_get_int(j, "missing", 42) == 42, "json_get_int 缺字段返回默认值");

    json_get_string(j, "s", buf, sizeof(buf));
    check(strcmp(buf, "hi there") == 0, "json_get_string 读字符串");
    check(json_get_string(j, "missing", buf, sizeof(buf)) != 0, "json_get_string 缺字段报错");

    char arr[4][ITEM_LEN];
    int n = json_array_strings("{\"p\":[\"/x\",\"/y\",\"/z\"]}", "p", arr, 4);
    check(n == 3 && strcmp(arr[2], "/z") == 0, "json_array_strings 读数组");
    check(json_array_strings("{\"p\":[]}", "p", arr, 4) == 0, "空数组返回 0");
    check(json_array_strings("{}", "p", arr, 4) == 0, "缺数组返回 0");

    /* 畸形 / NULL 输入不应崩溃 */
    json_escape(NULL, buf, sizeof(buf));
    check(buf[0] == 0, "json_escape(NULL) 输出空串且不崩溃");
    check(json_get_int(NULL, "a", 5) == 5, "json_get_int(NULL) 返回默认值");
    check(json_get_string(NULL, "a", buf, sizeof(buf)) != 0, "json_get_string(NULL) 报错不崩溃");
    check(json_array_strings(NULL, "a", arr, 4) == 0, "json_array_strings(NULL) 返回 0");
    check(json_get_int("{{{{", "a", 5) == 5, "畸形 JSON 返回默认值");
}

int main(void)
{
    test_rules();
    test_paths();
    test_json();
    printf("\n== 结果: %d 通过 / %d 失败 ==\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
