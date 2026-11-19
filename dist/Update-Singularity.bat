@echo off
setlocal
cd /d "%~dp0"
title Singularity Browser — Update
set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" set "PS_EXE=powershell.exe"
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Update-Singularity.ps1" -InstallDir "%~dp0"
if errorlevel 1 (
    echo.
    echo [ERROR] Update failed. Check your internet connection and try again.
    pause
)
endlocal
