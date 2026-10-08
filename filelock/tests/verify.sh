#!/usr/bin/env bash
# verify.sh — 一条命令跑完全部自检（开发/发版前用）
#   ./tests/verify.sh              常规构建 + 单测 + 冒烟 + 静态分析
#   ./tests/verify.sh --with-asan  额外跑 ASan/UBSan 模糊回归
#   ./tests/verify.sh --with-win   额外跑 Windows 交叉编译（需 mingw 工具链）
#   ./tests/verify.sh --all        以上全部
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"

ASAN=0; WIN=0
for a in "$@"; do
  case "$a" in
    --with-asan) ASAN=1 ;;
    --with-win)  WIN=1 ;;
    --all)       ASAN=1; WIN=1 ;;
    *) echo "未知参数: $a"; exit 2 ;;
  esac
done

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \xe2\x9c\x94 %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \xe2\x9c\x98 %s\n' "$1"; }
run() { # run <描述> <命令...>
  local desc="$1"; shift
  if "$@" >/tmp/fl_verify.log 2>&1; then ok "$desc"; else
    bad "$desc"; sed 's/^/      /' /tmp/fl_verify.log | tail -20
  fi
}

echo "== 1. 常规构建（零告警） =="
make clean >/dev/null 2>&1
if make >/tmp/fl_verify.log 2>&1; then
  W=$(grep -c 'warning:' /tmp/fl_verify.log || true)
  if [ "$W" -eq 0 ]; then ok "构建成功且零告警"; else bad "构建有 $W 条告警"; grep 'warning:' /tmp/fl_verify.log | head -5; fi
else
  bad "构建失败"; tail -20 /tmp/fl_verify.log
fi

echo "== 2. 单元测试 =="
run "make test" make test

echo "== 3. Web 冒烟测试 =="
run "tests/smoke_test.sh" bash tests/smoke_test.sh

if [ "$ASAN" -eq 1 ]; then
  echo "== 4. ASan/UBSan 模糊回归 =="
  make clean >/dev/null 2>&1
  if make CFLAGS="-O1 -g -Wall -Wextra -fsanitize=address,undefined -D_DEFAULT_SOURCE" >/tmp/fl_verify.log 2>&1; then
    run "tests/fuzz_api.sh" bash tests/fuzz_api.sh
  else
    bad "sanitizer 构建失败"; tail -20 /tmp/fl_verify.log
  fi
fi

if [ "$WIN" -eq 1 ]; then
  echo "== 5. Windows 交叉编译 =="
  MINGW=""
  for d in "$DIR"/../.openclaw/tmp/llvm-mingw-* /opt/llvm-mingw-* /usr/local/llvm-mingw-*; do
    [ -x "$d/bin/x86_64-w64-mingw32-gcc" ] && MINGW="$d" && break
  done
  if [ -n "$MINGW" ]; then
    make clean >/dev/null 2>&1
    if make OS=Windows_NT CC="$MINGW/bin/x86_64-w64-mingw32-gcc" >/tmp/fl_verify.log 2>&1; then
      W=$(grep -c 'warning:' /tmp/fl_verify.log || true)
      if [ "$W" -eq 0 ]; then ok "Windows 目标零告警"; else bad "Windows 目标有 $W 条告警"; grep 'warning:' /tmp/fl_verify.log | head -5; fi
    else
      bad "Windows 交叉编译失败"; tail -20 /tmp/fl_verify.log
    fi
  else
    echo "  - 跳过（找不到 llvm-mingw 工具链）"
  fi
fi

# 恢复常规构建，免得留下 sanitizer 版本
make clean >/dev/null 2>&1
make >/dev/null 2>&1

echo
echo "== 汇总: $PASS 通过 / $FAIL 失败 =="
[ "$FAIL" -eq 0 ]
