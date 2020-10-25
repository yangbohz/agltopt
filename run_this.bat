@echo off

set uactest=%systemroot%\system32\uactest.txt
(echo This file is used for UAC test and will be deleted soon > %uactest%) 1>nul 2>nul
if exist %uactest% (
    echo Now the script will run
    pause
    del %uactest%
    powershell Set-ExecutionPolicy Unrestricted
    cd /d %~dp0
    powershell -noexit  .\opt.ps1
) else (
    echo Please run as administrator
    pause
)