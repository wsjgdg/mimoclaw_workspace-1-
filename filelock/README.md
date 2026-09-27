# filelock — 文件占用诊断器 🔒

查明电脑上**文件为什么被占用**，并直接给出解决办法。带图形界面，支持 **Windows / macOS**（Linux 也能用）。

## ✨ 功能

**① 文件 / 文件夹检测**
- 一键扫描指定路径，列出**占用它的进程**（PID、进程名、程序路径）
- **支持拖拽**：把文件/文件夹直接拖进窗口即可（自动按文件名定位真实路径）
- 目录可勾选**递归扫描**（深入查找目录内被打开的文件）
- 逐项检查：读 / 写 / 删除权限、只读属性、符号链接、挂载状态、系统保护等
- 给出针对性的解决办法（含可直接复制的命令）
- **一键复制报告**：诊断结果格式化成文本，方便发给别人

**② 报错提示分析**
- 把系统弹出的报错提示**粘贴进来**，自动匹配原因并给出对策
- **剪贴板自动感知**：复制报错提示后自动弹出“立即分析”建议（可在界面关闭）
- **拖拽报错文本**进窗口也会自动分析
- 内置 14 类常见“占用/删除失败”报错规则（中英文）
- 自动识别提示中包含的文件路径，点击即可跳转检测占用进程

**③ 解除占用 / 删除**
- **🔓 释放占用（句柄级解锁）**：不结束进程，直接关闭占用句柄（Unlocker 同款原理：
  NtQuerySystemInformation 枚举句柄 + DuplicateHandle(DUPLICATE_CLOSE_SOURCE)），不丢未保存工作
- **🗑 删除**：检测完直接删，顽固文件可先释放占用再删
- 界面内一键结束占用进程（带确认提示）
- **右键菜单集成**：`filelock --install-menu` 后，资源管理器右键文件即可“用 filelock 查占用”

**④ 检测历史**
- 检测过的文件自动留档（本地 `~/.filelock_history.jsonl`，最多 200 条）
- 点击历史条目即可回填路径**重新检测**，支持一键清空

**⑤ 命令行增强**
- `--json` 输出 JSON（便于脚本/自动化处理）
- `--wait 秒` 轮询等待直到文件解除占用（适合脚本重试）

## 🖥 界面预览

双击启动后自动打开浏览器：

- 顶部切换两种模式：📁 文件检测 / 📋 报错分析
- 结果卡片：状态徽章（可读/可写/可删除）→ 占用进程表 → 原因分析 → 解决办法
- 报错分析结果中检测到的路径可点击直接检测

## 🔧 编译

构建时会自动把 web 界面打包进二进制（`tools/embed_web` 生成 `src/web_embedded.h`），
**单个可执行文件即可分发**，不带 web 目录也能跑（带了则优先生效，方便开发调试）。

### macOS
```bash
./build_mac.sh          # 或手动：
make
```

### Windows
双击 `build_win.bat`（自动识别 MSVC / MinGW），或手动：

```bat
rem MSVC（在 x64 Native Tools Command Prompt 中）
cl /O2 /W3 src\*.c /Fe:filelock.exe /link rstrtmgr.lib comdlg32.lib shell32.lib ole32.lib ws2_32.lib

rem MinGW
gcc -O2 -Wall src/*.c -o filelock.exe -lrstrtmgr -lcomdlg32 -lshell32 -lole32 -lws2_32
```

> 界面已内嵌，单文件即可分发；`web/` 目录可选（存在时优先生效）。
> 把文件拖到程序图标上也可以直接检测（等价于 `filelock 路径`）。

## 🚀 使用

```bash
./filelock                  # 图形界面：启动本地服务并自动打开浏览器
./filelock 路径             # 命令行：诊断该文件/文件夹
./filelock --paste "报错提示"  # 命令行：分析报错文本
./filelock -k 路径          # 命令行：强制结束占用进程
./filelock --json 路径      # JSON 输出（脚本友好）
./filelock --wait 30 路径   # 轮询等待直到解除占用
./filelock --install-menu   # Windows：注册资源管理器右键菜单
```

图形界面地址：`http://127.0.0.1:8632/`（仅监听本机，不对外网开放；端口占用自动顺延）

## 📁 项目结构

```
filelock/
├── src/
│   ├── main.c        入口：图形界面 / 命令行双模式
│   ├── diagnose.c    诊断引擎（Windows Restart Manager / lsof / /proc，含进程所属账户）
│   ├── rules.c       报错文本 → 原因/对策 规则库
│   ├── browse.c      原生文件选择对话框（Windows / macOS / Linux）
│   ├── clipboard.c   系统剪贴板读取（剪贴板自动感知）
│   ├── locate.c      按文件名定位真实路径（拖拽支持）
│   ├── history.c     检测历史留档
│   ├── close_handle.c 句柄级解锁（Windows，不杀进程）
│   ├── menu.c        资源管理器右键菜单集成
│   ├── jsonutil.c    JSON 读写小工具
│   ├── httpd.c       内置本地 HTTP 服务 + API（多线程）
│   ├── web_embedded.h  （构建时生成：内嵌界面资源）
│   └── filelock.h
├── tools/
│   └── embed_web.c   打包工具：web 文件 → C 数组
├── web/
│   ├── index.html    图形界面
│   ├── style.css
│   └── app.js
├── Makefile          macOS / Linux 构建
├── build_win.bat     Windows 构建（MSVC/MinGW 自动识别）
├── build_mac.sh      macOS 构建
└── archive/          早期命令行单文件版本（留档）
```

## 🔐 安全说明

- 服务只绑定 `127.0.0.1`，不对外网开放，不上传任何数据
- 剪贴板感知**只在本地读取、本地判断**，只有疑似报错的文本才会弹出建议，可随时在界面关闭
- 拖拽定位只在用户目录等常见位置**按文件名查找**，不上传文件内容
- 检测历史只存本机（`~/.filelock_history.jsonl`），可随时清空
- “结束进程”操作需要在界面中二次确认；命令行 `-k` 需显式指定

## ❓ 常见问题

**Windows：提示无法访问 / 占用查不到进程？**
→ 以管理员身份运行（右键 → 以管理员身份运行）；句柄级解锁需要管理员权限

**释放占用会丢数据吗？**
→ 不会结束进程，只是强制关闭它对目标文件的句柄；但对应程序后续对该文件的操作可能异常，建议先保存工作

**macOS：选择文件时提示没有权限？**
→ 系统设置 → 隐私与安全性 → 完全磁盘访问权限，给终端或 App 打勾

**macOS 想要 Finder 右键菜单？**
→ 打开“自动操作”→ 新建“快速操作”→ 添加“运行 Shell 脚本”（内容：`/path/to/filelock "$1"`）→ 保存后在
  系统设置 → 键盘 → 快捷键 → 服务 中绑定；或直接把文件拖到程序图标上

**报错提示匹配不到规则？**
→ 用“文件检测”直接扫描文件；或把报错文本反馈给开发者补充规则库
