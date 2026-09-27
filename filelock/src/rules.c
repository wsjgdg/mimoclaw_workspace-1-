/*
 * rules.c — 错误提示文本 → 原因/对策 规则库
 * 支持中英文常见“文件被占用/删除失败”报错，按关键词命中打分排序。
 */
#include "filelock.h"

typedef struct {
    const char *kw[12];       /* 任一命中即计分，英文大小写不敏感 */
    const char *cause;
    const char *fixes[8];
    int platform;             /* 0=通用 1=Windows 2=macOS */
} Rule;

static const Rule RULES[] = {
    { /* 1 */
        { "另一个程序正在使用此文件", "另一个程序正在使用此文件夹", "已被另一程序打开", "另一程序中打开",
          "being used by another process", "in use by", NULL },
        "文件/文件夹正被其他程序占用（Windows 典型的错误 32 占用提示）",
        { "关闭正在使用它的程序：办公软件、播放器、云盘同步、杀毒扫描等",
          "关闭资源管理器的“预览窗格”（查看 → 预览窗格）",
          "重启资源管理器：taskkill /f /im explorer.exe 然后运行 explorer.exe",
          "任务管理器 → 详细信息，按提示里的文件名搜进程，结束后再试",
          "顽固占用：用 Process Explorer 的 Handle → Find Handle 定位持有者",
          "以上无效：重启电脑后再删除", NULL },
        1
    },
    { /* 2 */
        { "操作无法完成，因为文件已在另一程序中打开", "操作无法完成，因为其中的文件夹或文件已在另一程序",
          "the action cannot be completed", "the operation can't be completed because the item is in use",
          "operation can't be completed", NULL },
        "Windows/资源管理器报告文件或文件夹被占用",
        { "确定哪个程序占用：见本工具“文件检测”结果里的占用进程列表",
          "目录被占用时，注意是否有程序以该目录为工作目录（命令行/下载工具常见）",
          "杀毒软件/Windows Defender 正在扫描时稍等 1-2 分钟再试",
          "关闭占用后执行删除；仍失败可重启资源管理器或注销重登", NULL },
        0
    },
    { /* 3 */
        { "拒绝访问", "需要权限", "需要提供管理员权限", "access is denied", "permission denied",
          "没有权限", "you require permission", "操作不被允许", "operation not permitted", NULL },
        "权限不足或被系统/安全策略保护",
        { "Windows：右键“以管理员身份运行”命令提示符/PowerShell 再操作",
          "Windows：右键文件 → 属性 → 安全 → 给当前账号添加完全控制权限",
          "macOS/Linux：chmod u+rwx 修正权限，或 sudo 操作",
          "macOS：系统设置 → 隐私与安全性 → 完全磁盘访问权限，给终端/应用打勾",
          "macOS：系统目录受 SIP 保护，请把文件移到用户目录再处理",
          "检查安全软件（杀毒/EDR/DLP）的锁定与隔离区", NULL },
        0
    },
    { /* 4 */
        { "资源忙", "text file busy", "text file busy", "设备或资源忙", "resource busy", "文件正在使用中", NULL },
        "文件正被系统/进程独占（正在运行的程序、挂载点、交换文件）",
        { "若是正在运行的程序/脚本：先停止运行再覆盖或删除",
          "macOS/Linux：sudo lsof -- \"文件路径\" 查看持有者",
          "检查是否为挂载点：mount | grep 该路径，先 umount 再操作", NULL },
        0
    },
    { /* 5 */
        { "只读", "read-only", "write-protected", "写保护", "read only file system", NULL },
        "文件或文件系统处于只读状态",
        { "Windows：attrib -R 文件路径  取消只读属性",
          "U盘/移动盘的物理写保护开关拨回可写",
          "macOS/Linux：文件系统只读挂载，检查磁盘健康或重新挂载 mount -o remount,rw",
          "macOS 系统卷(/System 等)默认只读，请勿直接修改", NULL },
        0
    },
    { /* 6 */
        { "回收站", "recycle bin", "$recycle.bin", "无法删除文件夹", "cannot delete folder", NULL },
        "回收站损坏或目录清理受阻",
        { "以管理员打开命令提示符执行：rd /s /q 文件夹完整路径",
          "重置回收站：删除 X:\\$Recycle.Bin（X 为盘符，需管理员）后重启",
          "关闭正在写入该目录的程序后再清理", NULL },
        1
    },
    { /* 7 */
        { "路径太长", "filename too long", "exceeds the maximum path", "name too long",
          "file name would be too long", "文件名、目录名或卷标语法不正确", NULL },
        "路径过长或文件名非法（Windows MAX_PATH 260 限制）",
        { "把文件先移动/复制到较短的目录（如 C:\\tmp）再删除",
          "Win10/11：启用长路径支持（组策略 LongPathsEnabled=1）",
          "命令行加 \\\\?\\ 前缀：del \\\\?\\C:\\very\\long\\path",
          "检查文件名是否含非法字符 : * ? \" < > |", NULL },
        1
    },
    { /* 8 */
        { "找不到指定的文件", "no such file", "cannot find", "系统找不到", "does not exist", NULL },
        "路径不存在（可能已被移动/改名/删除）",
        { "确认路径拼写与大小写（macOS 区分大小写）",
          "刷新资源管理器（F5）或重新打开对话框",
          "检查是否在网络盘/移动盘上，设备已断开", NULL },
        0
    },
    { /* 9 */
        { "损坏且无法读取", "corrupt", "cyclic redundancy", "crc", "数据错误", NULL },
        "文件系统或文件损坏",
        { "Windows：chkdsk X: /f （X 为盘符，可能需重启后检查）",
          "macOS：磁盘工具 → 急救；或 fsck -fy（恢复模式）",
          "重要数据先尝试复制出来，再修复磁盘", NULL },
        0
    },
    { /* 10 */
        { "没有空间", "no space left", "disk full", "磁盘空间不足", NULL },
        "磁盘空间不足导致无法写入/删除异常",
        { "清理磁盘：删除临时文件、清空回收站",
          "Windows：磁盘清理 cleanmgr；macOS：系统设置 → 储存空间",
          "检查目标盘与系统盘（临时目录所在盘）的剩余空间", NULL },
        0
    },
    { /* 11 */
        { "onedrive", "正在同步", "同步中", "云端文件", "sharepoint", "网盘", "dropbox", "google drive", NULL },
        "云盘/网盘同步程序正在占用或锁定文件",
        { "暂停同步（托盘图标右键 → 暂停）后再删除",
          "等待同步完成后再操作，避免来回抢占",
          "把文件移出同步目录（如 OneDrive 文件夹）再处理", NULL },
        0
    },
    { /* 12 */
        { "被占用", "占用中", "locked", "file is open", "file in use", "is being used", NULL },
        "文件被锁定/占用（通用匹配）",
        { "用本工具“文件检测”输入该文件路径，直接列出占用进程",
          "关闭可能使用它的程序：编辑器、播放器、数据库、下载工具",
          "Windows 顽固占用：重启资源管理器或重启系统",
          "macOS/Linux：sudo lsof -- \"文件路径\" 定位持有进程", NULL },
        0
    },
    { /* 13 */
        { "目录不是空的", "directory not empty", "dir not empty", NULL },
        "目录内仍有文件（可能隐藏文件或正在写入）",
        { "显示隐藏文件后再删（Windows：查看 → 隐藏的项目；macOS：Cmd+Shift+.）",
          "Windows：rd /s /q 目录路径",
          "检查是否有程序正在往目录里写文件（杀毒/同步/下载）", NULL },
        0
    },
    { /* 14 */
        { "另一个进程", "进程正在使用", "process cannot access", NULL },
        "进程占用导致无法访问",
        { "任务管理器结束相关进程后再试",
          "用本工具“文件检测”一键列出占用进程 PID 与程序名",
          "服务类占用（svchost 等）：重启对应服务或重启系统", NULL },
        1
    },
    { /* 15 */
        { "trustedinstaller", "您需要来自", "需要来自 ", "所有者", "requesting permission", NULL },
        "文件所有权/TrustedInstaller 保护（系统文件常见）",
        { "获取所有权：右键 → 属性 → 安全 → 高级 → 更改所有者",
          "命令行：takeown /f 文件 /r /d y 后再 icacls 文件 /grant 用户名:F",
          "若是系统组件，建议不要修改，改为替换用户目录下的副本", NULL },
        1
    },
    { /* 16 */
        { "0x80070020", "0x80070091", "0x80070057", "0x80004005", "hr=0x", "hresult", NULL },
        "Windows 错误码/HRESULT（0x80070020=被占用，0x80070091=目录非空，0x8007007e=找不到模块）",
        { "0x80070020：文件被占用 → 用本工具“文件检测”定位占用进程",
          "0x80070091：目录非空 → 显示隐藏文件后重删",
          "0x80004005：未指明错误 → 多为权限/磁盘问题，检查磁盘健康与权限", NULL },
        1
    },
    { /* 17 */
        { "正在打印", "spooler", "print job", "脱机打印", NULL },
        "打印队列占用（打印后台处理程序）",
        { "清空打印队列：services.msc → Print Spooler → 重启",
          "控制面板 → 设备和打印机 → 取消所有打印任务", NULL },
        1
    },
    { /* 18 */
        { "虚拟机", "vmdk", "vhdx", "vhd ", "virtualbox", "vmware", "hyper-v", NULL },
        "虚拟机磁盘文件被虚拟化软件占用",
        { "先关闭/挂起对应虚拟机再操作磁盘文件",
          "VirtualBox/VMware 界面里“解除注册”该虚拟磁盘", NULL },
        0
    },
    { /* 19 */
        { "数据库", "sqlite", ".db ", ".mdb", "database", "正在被使用", NULL },
        "数据库文件被数据库服务/程序占用",
        { "停止数据库服务或关闭打开它的程序",
          "SQLite：确保没有其他连接（可重启应用）", NULL },
        0
    },
    { /* 20 */
        { "不能弹出", "无法弹出", "设备正在使用", "弹出", "eject", "in use by another process", NULL },
        "U 盘/移动硬盘无法弹出（有程序占用卷）",
        { "关闭正在读写该盘的程序（资源管理器窗口、同步、备份）",
          "用本工具“文件检测”选盘符根目录查看占用进程",
          "仍是不行：注销或关机后再拔盘", NULL },
        0
    },
    { /* 21 */
        { "文件太大", "too large", "fat32", "exceeds the maximum size", NULL },
        "目标盘文件系统限制（FAT32 单文件最大 4GB）",
        { "把文件拆分/压缩后复制，或把 U 盘格式化为 exFAT/NTFS",
          "macOS/Linux 写 NTFS 需额外驱动，exFAT 兼容性最好", NULL },
        0
    },
    { /* 22 */
        { "已被锁定", "is locked", "文件被锁定", "item is locked", "文档已锁定", NULL },
        "文件带锁定标志/被标为锁定",
        { "macOS：选中文件 → 显示简介（Cmd+I）→ 取消“已锁定”勾选",
          "macOS/Linux：chflags nouchg 文件 / chattr -i 文件", NULL },
        2
    },
    { /* 23 */
        { "icloud", "time machine", "时间机器", "正在备份", "快照", NULL },
        "系统备份/同步服务占用（Time Machine 快照、iCloud 同步）",
        { "等备份/同步完成后再操作",
          "macOS：系统设置 → Time Machine → 排除该磁盘/暂停备份", NULL },
        2
    },
    { /* 24 */
        { "windows 无法访问指定设备路径或文件", "you may not have the appropriate permissions", NULL },
        "系统拒绝访问指定路径（权限或安全策略）",
        { "右键 → 属性 → 安全 → 检查当前用户权限",
          "组策略/杀毒可能拦截：临时关闭后重试",
          "用管理员身份运行命令提示符操作", NULL },
        1
    },
    { /* 25 */
        { "操作超时", "timed out", "timeout", "i/o error", "io error", "输入/输出错误", NULL },
        "I/O 错误或超时（磁盘硬件/网络盘不稳定）",
        { "检查磁盘健康（SMART）与数据线/网络连接",
          "Windows：chkdsk X: /f；macOS：磁盘工具 → 急救",
          "网络盘：重新挂载或换稳定网络后重试", NULL },
        0
    },
    { /* 26 */
        { "另一用户", "另一个用户", "被其他用户", "another user", "fast user switching", NULL },
        "其他用户会话占用（快速切换/远程桌面）",
        { "切换到对应用户会话关闭程序",
          "任务管理器 → 用户 → 注销多余会话", NULL },
        1
    }
};

#define N_RULES ((int)(sizeof(RULES) / sizeof(RULES[0])))

static void tolower_copy(const char *in, char *out, size_t n)
{
    size_t i = 0;
    for (; in[i] && i + 1 < n; i++) {
        unsigned char c = (unsigned char)in[i];
        out[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
    }
    out[i] = 0;
}

int analyze_text(const char *text, RuleHit *hits, int max)
{
    char lower[16384];
    tolower_copy(text, lower, sizeof(lower));

    int n = 0;
    for (int i = 0; i < N_RULES && n < max; i++) {
        int score = 0;
        for (int k = 0; RULES[i].kw[k]; k++) {
            char kw[128];
            tolower_copy(RULES[i].kw[k], kw, sizeof(kw));
            if (strstr(lower, kw)) score++;
        }
        if (score == 0) continue;

        RuleHit *h = &hits[n];
        memset(h, 0, sizeof(*h));
        h->hits = score;
        h->platform = RULES[i].platform;
        snprintf(h->cause, ITEM_LEN, "%s", RULES[i].cause);
        for (int f = 0; RULES[i].fixes[f] && h->nfixes < 8; f++)
            snprintf(h->fixes[h->nfixes++], ITEM_LEN, "%s", RULES[i].fixes[f]);
        n++;
    }

    /* 按命中数降序（简单插入排序） */
    for (int i = 1; i < n; i++) {
        RuleHit tmp = hits[i];
        int j = i - 1;
        while (j >= 0 && hits[j].hits < tmp.hits) { hits[j + 1] = hits[j]; j--; }
        hits[j + 1] = tmp;
    }
    return n;
}

/* 判断结尾是否为需要剔除的标点（支持 UTF-8 多字节标点） */
static int ends_with_punct(const char *start, const char *e)
{
    static const char *puncts[] = { "。", "，", "）", ";", "；", ")", ",", ".", "】", "】", "”", "\"", NULL };
    for (int i = 0; puncts[i]; i++) {
        size_t pl = strlen(puncts[i]);
        if ((size_t)(e - start) >= pl && memcmp(e - pl, puncts[i], pl) == 0) return 1;
    }
    return 0;
}

/* 从提示文本中提取可能的文件路径（Windows 盘符路径 / POSIX 绝对路径） */
int extract_paths(const char *text, char out[][ITEM_LEN], int max)
{
    int count = 0;
    const char *p = text;
    while (*p && count < max) {
        const char *start = NULL;
        /* Windows: X:\ 或 X:/ */
        if (((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')) &&
            p[1] == ':' && (p[2] == '\\' || p[2] == '/')) start = p;
        /* POSIX 绝对路径：/ 后跟字母数字 */
        else if (*p == '/' && ((p[1] >= 'A' && p[1] <= 'Z') || (p[1] >= 'a' && p[1] <= 'z') || p[1] == '_'))
            start = p;

        if (!start) { p++; continue; }

        const char *e = start;
        while (*e && (unsigned char)*e >= 0x20 && *e != '"' && *e != '\'' && *e != '<' && *e != '>' &&
               *e != '|' && *e != '*' && *e != '?' && *e != '\n' && *e != '\r')
            e++;
        /* 去掉结尾标点 */
        while (e > start && ends_with_punct(start, e)) {
            static const char *puncts[] = { "。", "，", "）", ";", "；", ")", ",", ".", "】", "”", NULL };
            size_t cut = 1;
            for (int i = 0; puncts[i]; i++) {
                size_t pl = strlen(puncts[i]);
                if ((size_t)(e - start) >= pl && memcmp(e - pl, puncts[i], pl) == 0) { cut = pl; break; }
            }
            e -= cut;
        }
        size_t len = (size_t)(e - start);
        if (len >= 4) {
            int dup = 0;
            for (int i = 0; i < count; i++)
                if (strlen(out[i]) == len && strncmp(out[i], start, len) == 0) { dup = 1; break; }
            if (!dup) {
                snprintf(out[count], ITEM_LEN, "%.*s", (int)len, start);
                count++;
            }
        }
        p = e > p ? e : p + 1;
    }
    return count;
}
