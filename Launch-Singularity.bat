@echo off
setlocal
cd /d "%~dp0"
title Singularity Browser v1.0.0

if exist ".\singularity.exe" (
    start "" ".\singularity.exe"
) else if exist ".\dist\singularity.exe" (
    start "" ".\dist\singularity.exe"
) else (
    echo [ERROR] singularity.exe not found. Download Singularity-Setup.exe from https://github.com/MyMasha/Singularity/releases
    pause
)
exit
