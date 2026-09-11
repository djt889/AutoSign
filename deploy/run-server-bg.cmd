@echo off
rem ============================================================
rem  AutoSign 后台常驻启动(供 Windows 计划任务调用,无窗口)
rem  日志写入 data\server-task.log
rem  前置:先双击 start-server.cmd 完成一次初始化(建 .venv + 装依赖)
rem ============================================================
setlocal
cd /d "%~dp0.."
if "%JUSTSIGN_PORT%"=="" set JUSTSIGN_PORT=37421
set PYTHONUTF8=1

rem 优先用已初始化的虚拟环境,回退到系统 Python
set PYW=.venv\Scripts\pythonw.exe
if not exist "%PYW%" set PYW=pythonw

if not exist "data" mkdir "data"
"%PYW%" -m pc.main >> "data\server-task.log" 2>&1
