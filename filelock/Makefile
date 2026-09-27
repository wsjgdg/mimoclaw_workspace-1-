# filelock — 文件占用诊断器
#   make          构建 ./filelock（macOS / Linux）
#   make run      构建并启动图形界面
#   make clean    清理

CC      ?= cc
# _DEFAULT_SOURCE: 严格模式下显式暴露 nanosleep/strcasestr 等 POSIX 扩展
CFLAGS  += -D_DEFAULT_SOURCE
CFLAGS  ?= -O2 -Wall -Wextra
BIN     := filelock
EMBED   := src/web_embedded.h
SRC     := src/main.c src/diagnose.c src/rules.c src/browse.c src/clipboard.c src/locate.c src/history.c src/close_handle.c src/menu.c src/jsonutil.c src/httpd.c

ifeq ($(OS),Windows_NT)
  LDFLAGS := -lws2_32 -lcomdlg32 -lshell32 -lole32 -ladvapi32
  BIN := filelock.exe
else
  UNAME := $(shell uname -s)
  LDFLAGS := -pthread
endif

all: $(BIN)

# 把 web 界面打包进二进制（单文件分发）
tools/embed_web: tools/embed_web.c
	$(CC) $(CFLAGS) tools/embed_web.c -o tools/embed_web

$(EMBED): tools/embed_web web/index.html web/app.js web/style.css
	tools/embed_web $(EMBED) EMB_INDEX_HTML web/index.html EMB_APP_JS web/app.js EMB_STYLE_CSS web/style.css

$(BIN): $(SRC) src/filelock.h $(EMBED)
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LDFLAGS)

run: $(BIN)
	./$(BIN)

clean:
	rm -f $(BIN) filelock.exe tools/embed_web tools/embed_web.exe

.PHONY: all run clean
