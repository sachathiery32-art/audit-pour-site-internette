@echo off
title AutoSecAudit
cd /d "%~dp0"

REM Try py launcher first (real Python install), then fall back to python
where py >nul 2>nul
if %errorlevel%==0 (
    py autosecaudit.py %*
) else (
    python autosecaudit.py %*
)
pause
