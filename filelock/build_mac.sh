#!/bin/bash
# filelock macOS 构建脚本
set -e
cd "$(dirname "$0")"

CC=${CC:-clang}
echo "[1/3] 生成内嵌界面（单文件分发）..."
$CC -O2 tools/embed_web.c -o tools/embed_web
./tools/embed_web src/web_embedded.h EMB_INDEX_HTML web/index.html EMB_APP_JS web/app.js EMB_STYLE_CSS web/style.css

echo "[2/3] 编译..."
$CC -O2 -Wall -Wextra src/main.c src/diagnose.c src/rules.c src/browse.c src/clipboard.c src/locate.c src/history.c src/close_handle.c src/menu.c src/jsonutil.c src/httpd.c -o filelock

echo "[3/3] 完成 ✔"
echo "  启动图形界面：  ./filelock"
echo "  命令行诊断：    ./filelock <文件或目录路径>"
