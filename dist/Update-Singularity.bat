@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
cd /d "%SCRIPT_DIR%"
title Singularity Browser - Update

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" (
    echo [ERROR] Windows PowerShell not found at "%PS_EXE%".
    pause
    endlocal
    exit /b 1
)

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%\Update-Singularity.ps1" -InstallDir "%SCRIPT_DIR%"
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
    echo.
    echo [ERROR] Update failed. Check your internet connection and signing configuration, then try again.
    pause
)
endlocal & exit /b %EXIT_CODE%
