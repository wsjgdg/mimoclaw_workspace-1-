@echo off
rem =====================================================
rem  filelock Windows 构建脚本
rem  用法：双击运行，或在 cmd 中执行 build_win.bat
rem  支持 MSVC(cl) 或 MinGW(gcc)，自动检测已安装的编译器
rem =====================================================
setlocal

rem [1/3] 生成内嵌界面（单文件分发）
where cl >nul 2>nul
if %errorlevel%==0 (
    cl /nologo tools\embed_web.c /Fe:tools\embed_web.exe >nul 2>&1
) else (
    gcc -O2 tools\embed_web.c -o tools\embed_web.exe 2>nul
)
if not exist tools\embed_web.exe (
    echo [错误] 无法构建打包工具 tools\embed_web.exe
    pause
    exit /b 1
)
tools\embed_web.exe src\web_embedded.h EMB_INDEX_HTML web\index.html EMB_APP_JS web\app.js EMB_STYLE_CSS web\style.css
if not exist src\web_embedded.h (
    echo [错误] 生成内嵌界面失败
    pause
    exit /b 1
)

where cl >nul 2>nul
if %errorlevel%==0 (
    echo [1/1] 使用 MSVC 编译...
    cl /O2 /W3 /D_CRT_SECURE_NO_WARNINGS src\main.c src\diagnose.c src\rules.c src\browse.c src\clipboard.c src\locate.c src\history.c src\close_handle.c src\menu.c src\jsonutil.c src\httpd.c /Fe:filelock.exe /link rstrtmgr.lib comdlg32.lib shell32.lib ole32.lib ws2_32.lib advapi32.lib
    if %errorlevel% neq 0 goto :fail
    goto :ok
)

where gcc >nul 2>nul
if %errorlevel%==0 (
    echo [1/1] 使用 MinGW gcc 编译...
    gcc -O2 -Wall src\main.c src\diagnose.c src\rules.c src\browse.c src\clipboard.c src\locate.c src\history.c src\close_handle.c src\menu.c src\jsonutil.c src\httpd.c -o filelock.exe -lrstrtmgr -lcomdlg32 -lshell32 -lole32 -lws2_32 -ladvapi32
    if %errorlevel% neq 0 goto :fail
    goto :ok
)

echo [错误] 未找到 cl(MSVC) 或 gcc(MinGW)。
echo   MSVC  : 从“x64 Native Tools Command Prompt for VS”运行本脚本
echo   MinGW : 安装 https://www.mingw-w64.org/ 后重试
pause
exit /b 1

:ok
echo.
echo ✔ 构建完成：filelock.exe（界面已内嵌，单文件即可分发）
echo   双击 filelock.exe 即可打开图形界面
echo   可选：filelock.exe --install-menu 注册右键菜单
pause
exit /b 0

:fail
echo.
echo ✘ 构建失败，请把上方错误信息反馈给开发者
pause
exit /b 1
