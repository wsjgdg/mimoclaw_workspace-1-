#!/usr/bin/env bash
# fuzz_api.sh — 对 sanitizer 构建的服务端打畸形请求，检查 ASan/UBSan 报告
# 前置: make CFLAGS="-O1 -g -Wall -Wextra -fsanitize=address,undefined -D_DEFAULT_SOURCE"
# 用法: ./tests/fuzz_api.sh [端口]
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$DIR/filelock"
PORT="${1:-39777}"
B="http://127.0.0.1:$PORT"
LOG="${FL_FUZZ_LOG:-/tmp/fl_fuzz_srv.log}"

[ -x "$BIN" ] || { echo "未找到 $BIN"; exit 1; }

: > "$LOG"
"$BIN" --no-open -p "$PORT" > "$LOG" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null' EXIT

for i in $(seq 1 50); do
  curl -s -m 2 "$B/api/health" | grep -q healthy && break
  sleep 0.1
done

INIT=$(curl -s -m 5 "$B/api/init")
TOK=$(printf '%s' "$INIT" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))')
A=(-H "X-Filelock-Token: $TOK" -H 'Content-Type: application/json')
echo "token_len=${#TOK}"

LONG=$(python3 -c 'print("bad path in use "*200)')
LONGPATH=$(python3 -c 'print("x"*4000)')
HUGE=$(python3 -c 'print("y"*60000)')

while IFS= read -r body; do
  [ -n "$body" ] && curl -s -m 10 -X POST "${A[@]}" "$B/api/scan" -d "$body" >/dev/null
done <<EOF
{"path":"/etc/passwd"}
{"path":"/nonexistent/aa"}
{"path":"/tmp","deep":1}
{"path":"$LONGPATH"}
{}
{"path":null}
{"path":["a"]}
{"path":"/tmp","deep":"x"}
{"path":"$LONG","deep":1}
{"path":"$HUGE"}
{"path":"'; rm -rf / ; '"}
EOF

curl -s -m 10 -X POST "${A[@]}" "$B/api/analyze"   -d "{\"text\":\"$LONG\"}" >/dev/null
curl -s -m 10 -X POST "${A[@]}" "$B/api/analyze"   -d '{"text":""}' >/dev/null
curl -s -m 10 -X POST "${A[@]}" "$B/api/act"       -d '{"op":"delete","path":"/tmp/definitely_not_here"}' >/dev/null
curl -s -m 10 -X POST "${A[@]}" "$B/api/act"       -d '{"op":"unlock","path":"/tmp","pid":"1;rm -rf /"}' >/dev/null
curl -s -m 10 -X POST "${A[@]}" "$B/api/act"       -d '{"op":"__proto__","path":"/tmp"}' >/dev/null
curl -s -m 10 "$B/api/history?page=9999999999&per=-5" >/dev/null
curl -s -m 10 "$B/api/history?page=abc&per=xyz" >/dev/null
curl -s -m 10 "$B/api/history?page=-1&per=0" >/dev/null
curl -s -m 10 "$B/api/clipboard" >/dev/null
curl -s -m 10 -X POST "${A[@]}" "$B/api/locate"    -d '{"name":"../etc/passwd"}' >/dev/null
curl -s -m 10 -X POST "${A[@]}" "$B/api/locate"    -d "{\"name\":\"$LONG\"}" >/dev/null
curl -s -m 10 -X POST "${A[@]}" "$B/api/scan-batch" -d '{"paths":["/etc","/tmp","/nonexistent"]}' >/dev/null
curl -s -m 10 -X POST "${A[@]}" "$B/api/scan-batch" -d '{"paths":[]}' >/dev/null
curl -s -m 10 -X POST "${A[@]}" "$B/api/kill"      -d '{"pid":-1}' >/dev/null
curl -s -m 10 -X POST "${A[@]}" "$B/api/kill"      -d '{"pid":999999999}' >/dev/null

sleep 0.6
echo "== sanitizer 报告 =="
if grep -qiE "sanitizer|runtime error|ERROR: Address|SUMMARY:|LeakSanitizer" "$LOG"; then
  grep -iE "sanitizer|runtime error|ERROR: Address|SUMMARY:|LeakSanitizer" "$LOG" | head -20
  echo "✘ 发现问题（完整日志: $LOG）"
  exit 1
fi
echo "✔ 干净（服务端无 sanitizer 报告）"
exit 0
