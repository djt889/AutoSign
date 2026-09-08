@echo off
rem AutoSign 后台常驻启动(供计划任务调用,无窗口)
cd /d E:\AI\OhMyZcode\justsign
set JUSTSIGN_PORT=37421
C:\Python313\pythonw.exe -m pc.main >> data\server-task.log 2>&1
