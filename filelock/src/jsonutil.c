/*
 * jsonutil.c — 极简 JSON 读写工具（够用即可，不引入第三方库）
 */
#include "filelock.h"

void json_escape(const char *in, char *out, size_t n)
{
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && o + 8 < n; p++) {
        switch (*p) {
        case '"':  out[o++] = '\\'; out[o++] = '"';  break;
        case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
        case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
        case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
        case '\t': out[o++] = '\\'; out[o++] = 't';  break;
        case '\b': out[o++] = '\\'; out[o++] = 'b';  break;
        case '\f': out[o++] = '\\'; out[o++] = 'f';  break;
        default:
            if (*p < 0x20) {
                o += (size_t)snprintf(out + o, n - o, "\\u%04x", *p);
            } else {
                out[o++] = (char)*p;
            }
        }
    }
    out[o] = 0;
}

/* 提取整数字段；不存在返回 def */
int json_get_int(const char *json, const char *key, int def)
{
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return def;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p == '"') { p++; return atoi(p); }   /* 数字被当成字符串传 */
    return atoi(p);
}

/* 提取 JSON 字符串数组：{"key":["a","b"]} → out[][]，返回条数 */
int json_array_strings(const char *json, const char *key, char out[][ITEM_LEN], int max)
{
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p && *p != '[') p++;
    if (!*p) return 0;
    p++;

    int n = 0;
    while (*p && *p != ']' && n < max) {
        while (*p && *p != '"' && *p != ']') p++;
        if (*p != '"') break;
        p++;
        size_t o = 0;
        while (*p && *p != '"' && o + 1 < ITEM_LEN) {
            if (*p == '\\' && p[1]) p++;
            out[n][o++] = *p++;
        }
        out[n][o] = 0;
        if (*p == '"') p++;
        if (o > 0) n++;
    }
    return n;
}

/* 从 JSON 中提取字符串字段值（处理转义，支持 \uXXXX 基本平面） */
int json_get_string(const char *json, const char *key, char *out, size_t n)
{
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p != '"') return -1;
    p++;

    size_t o = 0;
    while (*p && *p != '"' && o + 8 < n) {
        if (*p == '\\') {
            p++;
            switch (*p) {
            case 'n': out[o++] = '\n'; break;
            case 'r': out[o++] = '\r'; break;
            case 't': out[o++] = '\t'; break;
            case 'b': out[o++] = '\b'; break;
            case 'f': out[o++] = '\f'; break;
            case '/': out[o++] = '/';  break;
            case '"': out[o++] = '"';  break;
            case '\\': out[o++] = '\\'; break;
            case 'u': {
                unsigned cp = 0;
                int ok = 1;
                for (int i = 0; i < 4; i++) {
                    char c = p[1 + i];
                    unsigned v;
                    if (c >= '0' && c <= '9') v = (unsigned)(c - '0');
                    else if (c >= 'a' && c <= 'f') v = (unsigned)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') v = (unsigned)(c - 'A' + 10);
                    else { ok = 0; break; }
                    cp = cp * 16 + v;
                }
                if (!ok) break;
                p += 4;
                if (cp < 0x80) out[o++] = (char)cp;
                else if (cp < 0x800) {
                    out[o++] = (char)(0xC0 | (cp >> 6));
                    out[o++] = (char)(0x80 | (cp & 0x3F));
                } else {
                    out[o++] = (char)(0xE0 | (cp >> 12));
                    out[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    out[o++] = (char)(0x80 | (cp & 0x3F));
                }
                break;
            }
            default: out[o++] = *p; break;
            }
            if (*p) p++;
        } else {
            out[o++] = *p++;
        }
    }
    out[o] = 0;
    return 0;
}
