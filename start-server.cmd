@echo off
rem AutoSign 服务器前台启动脚本(双击运行,显示日志,Ctrl+C 停止)
chcp 65001 >nul
title AutoSign 自动签到服务器
cd /d %~dp0
set JUSTSIGN_PORT=37421
echo ===============================================
echo  AutoSign 服务器启动中 ... 端口 37421
echo  WebUI: http://127.0.0.1:37421
echo  按 Ctrl+C 停止服务
echo ===============================================
C:\Python313\python.exe -m pc.main
echo.
echo 服务已退出,按任意键关闭窗口
pause >nul
