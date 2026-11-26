@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
cd /d "%SCRIPT_DIR%"
title Singularity Browser v3.0.0

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

if /i "%~1"=="--update" (
    if not exist "%PS_EXE%" (
        echo [ERROR] Windows PowerShell not found at "%PS_EXE%".
        pause
        endlocal
        exit /b 1
    )
    if exist "%SCRIPT_DIR%\dist\Update-Singularity.ps1" (
        "%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%\dist\Update-Singularity.ps1" -InstallDir "%SCRIPT_DIR%"
        set "EXIT_CODE=%ERRORLEVEL%"
        endlocal & exit /b %EXIT_CODE%
    )
    echo [ERROR] Updater script not found at "%SCRIPT_DIR%\dist\Update-Singularity.ps1".
    pause
    endlocal
    exit /b 1
)

if exist "%SCRIPT_DIR%\singularity.exe" (
    start "" "%SCRIPT_DIR%\singularity.exe"
    endlocal & exit /b 0
) else if exist "%SCRIPT_DIR%\dist\singularity.exe" (
    start "" "%SCRIPT_DIR%\dist\singularity.exe"
    endlocal & exit /b 0
) else if exist "%LOCALAPPDATA%\Programs\Singularity\singularity.exe" (
    start "" "%LOCALAPPDATA%\Programs\Singularity\singularity.exe"
    endlocal & exit /b 0
) else (
    echo [ERROR] singularity.exe not found. Download Singularity-setup.exe from https://github.com/MyMasha/Singularity/releases
    pause
    endlocal & exit /b 1
)
