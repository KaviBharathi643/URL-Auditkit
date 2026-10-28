@echo off
title URL Audit Kit - Stopping Services
cd /d "%~dp0"

echo ============================================================
echo           Stopping URL Audit Kit Services...
echo ============================================================
echo.

echo [*] Terminating Backend on port 8765...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8765" ^| findstr "LISTENING"') do (
    taskkill /f /pid %%a >nul 2>&1
)

echo [*] Terminating Frontend on port 3000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3000" ^| findstr "LISTENING"') do (
    taskkill /f /pid %%a >nul 2>&1
)

:: Close any named cmd windows
taskkill /fi "WINDOWTITLE eq URL Audit Kit - Backend*" /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq URL Audit Kit - Frontend*" /f >nul 2>&1

echo.
echo [*] All URL Audit Kit services have been stopped.
echo.
pause
