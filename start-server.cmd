@echo off
rem ============================================================
rem  AutoSign WebUI 启动脚本(Windows)
rem  双击运行:首次会自动建虚拟环境并装依赖,之后直接启动
rem  Ctrl+C 停止服务
rem ============================================================
setlocal
chcp 65001 >nul
title AutoSign WebUI
cd /d "%~dp0"

if "%JUSTSIGN_PORT%"=="" set "JUSTSIGN_PORT=37421"
set "VENV=.venv"
set "PYEXE=%VENV%\Scripts\python.exe"

echo ===============================================
echo   AutoSign  WebUI  http://127.0.0.1:%JUSTSIGN_PORT%
echo -----------------------------------------------
echo   按 Ctrl+C 停止服务
echo ===============================================
echo.

if exist "%PYEXE%" goto run

rem ---------- 找系统 Python ----------
set "SYS_PY="
where py >nul 2>nul && set "SYS_PY=py -3"
if not defined SYS_PY where python >nul 2>nul && set "SYS_PY=python"
if not defined SYS_PY goto nopython

rem ---------- 建虚拟环境 + 装依赖(仅首次) ----------
echo [初始化] 首次运行,正在创建虚拟环境...
%SYS_PY% -m venv "%VENV%"
if errorlevel 1 goto venvfail

echo [初始化] 正在安装依赖(需要几分钟)...
"%PYEXE%" -m pip install --upgrade pip >nul 2>nul
"%PYEXE%" -m pip install -r pc\requirements.txt
if errorlevel 1 goto depfail

echo.
echo [提示] 依赖安装完成。
echo        如需「全自动授权」,请再执行一次以下命令安装浏览器内核:
echo            %VENV%\Scripts\python.exe -m scrapling install
echo        不装也能用,授权时改走「手动浏览器」方式即可。
echo.

:run
set "PYTHONUTF8=1"
"%PYEXE%" -m pc.main
set "EC=%errorlevel%"
echo.
if not "%EC%"=="0" goto crashed
echo 服务已停止。
pause
exit /b 0

:nopython
echo [错误] 未检测到 Python。
echo        请先安装 Python 3.10 或更高版本: https://www.python.org/downloads/
echo        安装时请勾选 "Add Python to PATH"。
echo.
pause
exit /b 1

:venvfail
echo [错误] 创建虚拟环境失败,请确认 Python 安装完整。
pause
exit /b 1

:depfail
echo [错误] 依赖安装失败,请检查网络后重试。
pause
exit /b 1

:crashed
echo [错误] 服务异常退出(代码 %EC%^)。
echo        常见原因:端口 %JUSTSIGN_PORT% 已被占用。
echo        换端口重试:  set JUSTSIGN_PORT=37555 ^&^& start-server.cmd
pause
exit /b 1
