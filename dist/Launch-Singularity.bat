@echo off
setlocal
cd /d "%~dp0"
title Singularity Browser v1.0.0

if exist ".\singularity.exe" (
    start "" ".\singularity.exe"
) else (
    echo [ERROR] singularity.exe not found. Download the latest release from https://github.com/MyMasha/Singularity/releases
    pause
)
exit
