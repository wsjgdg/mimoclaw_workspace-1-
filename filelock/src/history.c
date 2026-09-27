/*
 * history.c — 检测历史记录（本地留档，JSON Lines 格式）
 * 存储位置：
 *   Windows: %APPDATA%\filelock_history.jsonl
 *   其他    : $HOME/.filelock_history.jsonl
 */
#include "filelock.h"
#include <time.h>

#ifdef _WIN32
#  include <process.h>
#else
#  include <pthread.h>
#endif

#define HISTORY_FILE_MAX 200   /* 超过则截断保留最近 150 条 */

/* 简单互斥锁，避免并发写坏文件 */
#ifdef _WIN32
static CRITICAL_SECTION g_hist_lock;
static int g_hist_init = 0;
static void hist_lock(void)
{
    if (!g_hist_init) { InitializeCriticalSection(&g_hist_lock); g_hist_init = 1; }
    EnterCriticalSection(&g_hist_lock);
}
static void hist_unlock(void) { LeaveCriticalSection(&g_hist_lock); }
#else
static pthread_mutex_t g_hist_lock = PTHREAD_MUTEX_INITIALIZER;
static void hist_lock(void) { pthread_mutex_lock(&g_hist_lock); }
static void hist_unlock(void) { pthread_mutex_unlock(&g_hist_lock); }
#endif

static void history_file(char *out, size_t n)
{
#ifdef _WIN32
    char appdata[1024] = "";
    DWORD len = GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));
    if (len == 0 || len >= sizeof(appdata)) snprintf(appdata, sizeof(appdata), ".");
    snprintf(out, n, "%s\\filelock_history.jsonl", appdata);
#else
    const char *home = getenv("HOME");
    snprintf(out, n, "%s/.filelock_history.jsonl", home && home[0] ? home : ".");
#endif
}

int history_add(const char *path, const Report *r)
{
    char hf[2048], esc_path[ITEM_LEN * 2], esc_con[ITEM_LEN * 2];
    history_file(hf, sizeof(hf));
    json_escape(path, esc_path, sizeof(esc_path));
    json_escape(!r->exists ? "路径不存在或无法访问" :
                (r->nlockers > 0 ? "找到占用进程" :
                 (r->restricted ? "找到受限原因" : "没有被占用")), esc_con, sizeof(esc_con));

    hist_lock();
    FILE *f = fopen(hf, "a");
    if (!f) { hist_unlock(); return -1; }
    fprintf(f, "{\"path\":\"%s\",\"conclusion\":\"%s\",\"exists\":%d,\"nlockers\":%d,"
               "\"restricted\":%d,\"ts\":%ld}\n",
            esc_path, esc_con, r->exists, r->nlockers, r->restricted, (long)time(NULL));
    fclose(f);

    /* 超量截断：保留最近 HISTORY_FILE_MAX-50 条 */
    FILE *rf = fopen(hf, "r");
    if (rf) {
        int lines = 0;
        char buf[2048];
        while (fgets(buf, sizeof(buf), rf)) lines++;
        fclose(rf);
        if (lines > HISTORY_FILE_MAX) {
            FILE *rf2 = fopen(hf, "r");
            char *keep = (char *)malloc((size_t)lines * 2048);
            if (rf2 && keep) {
                char *store = keep;
                int skip = lines - (HISTORY_FILE_MAX - 50);
                int idx = 0;
                while (fgets(store, 2048, rf2)) {
                    if (idx++ < skip) continue;
                    store += strlen(store);
                }
                fclose(rf2);
                FILE *wf = fopen(hf, "w");
                if (wf) { fputs(keep, wf); fclose(wf); }
            } else if (rf2) fclose(rf2);
            free(keep);
        }
    }
    hist_unlock();
    return 0;
}

int history_list(HistoryItem *out, int max)
{
    char hf[2048];
    history_file(hf, sizeof(hf));
    hist_lock();
    FILE *f = fopen(hf, "r");
    if (!f) { hist_unlock(); return 0; }

    /* 先全部读入，再倒序输出（最新的在前） */
    char **lines = (char **)calloc((size_t)max + 200, sizeof(char *));
    int n = 0;
    char buf[2048];
    while (fgets(buf, sizeof(buf), f) && n < max + 199) {
        lines[n] = (char *)malloc(strlen(buf) + 1);
        if (lines[n]) strcpy(lines[n], buf);
        n++;
    }
    fclose(f);
    hist_unlock();

    int count = 0;
    for (int i = n - 1; i >= 0 && count < max; i--) {
        if (!lines[i]) continue;
        HistoryItem *h = &out[count];
        memset(h, 0, sizeof(*h));
        json_get_string(lines[i], "path", h->path, sizeof(h->path));
        json_get_string(lines[i], "conclusion", h->conclusion, sizeof(h->conclusion));
        h->exists = atoi(strstr(lines[i], "\"exists\":") ? strstr(lines[i], "\"exists\":") + 9 : "0");
        char *p;
        p = strstr(lines[i], "\"nlockers\":");  h->nlockers = p ? atoi(p + 11) : 0;
        p = strstr(lines[i], "\"restricted\":"); h->restricted = p ? atoi(p + 12) : 0;
        p = strstr(lines[i], "\"ts\":");         h->ts = p ? (long long)atol(p + 5) : 0;
        if (h->path[0]) count++;
    }
    for (int i = 0; i < n; i++) free(lines[i]);
    free(lines);
    return count;
}

int history_clear(void)
{
    char hf[2048];
    history_file(hf, sizeof(hf));
    hist_lock();
    int rc = remove(hf);
    hist_unlock();
    return rc == 0 ? 0 : -1;
}
