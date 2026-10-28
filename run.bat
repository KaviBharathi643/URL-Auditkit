@echo off
setlocal enabledelayedexpansion

title URL Audit Kit - Launcher
cd /d "%~dp0"

echo ============================================================
echo           URL Audit Kit - Single-Click Launcher
echo ============================================================
echo.

:: Detect Python
set "PYTHON_CMD="
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYTHON_CMD=%~dp0.venv\Scripts\python.exe"
) else (
    where python >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON_CMD=python"
    )
)

if "%PYTHON_CMD%"=="" (
    echo [ERROR] Python is not installed or not found in PATH!
    echo Please install Python 3.10+ and try again.
    pause
    exit /b 1
)

:: Detect Node / npm
where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] npm is not found in PATH!
    echo Please install Node.js and try again.
    pause
    exit /b 1
)

:: Free ports 8765 and 3000 if occupied
echo [*] Checking and freeing ports 8765 and 3000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8765" ^| findstr "LISTENING"') do (
    taskkill /f /pid %%a >nul 2>&1
)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3000" ^| findstr "LISTENING"') do (
    taskkill /f /pid %%a >nul 2>&1
)

:: Start Backend in separate window
echo [*] Starting FastAPI Backend on http://127.0.0.1:8765...
start "URL Audit Kit - Backend (FastAPI)" cmd /k "cd /d "%~dp0" && "%PYTHON_CMD%" -m webapp"

:: Wait for backend initialization (3 seconds)
ping 127.0.0.1 -n 4 >nul

:: Start Frontend in separate window
echo [*] Starting Next.js Frontend on http://localhost:3000...
start "URL Audit Kit - Frontend (Next.js)" cmd /k "cd /d "%~dp0frontend" && npm run dev"

:: Wait for frontend dev server to spin up (5 seconds)
echo [*] Waiting for services to initialize...
ping 127.0.0.1 -n 6 >nul

:: Open browser automatically
echo [*] Opening dashboard in your default browser...
start http://localhost:3000

echo.
echo ============================================================
echo   URL Audit Kit is running!
echo ============================================================
echo   Frontend Dashboard:   http://localhost:3000
echo   FastAPI Backend:      http://127.0.0.1:8765
echo   Interactive API Docs: http://127.0.0.1:8765/docs
echo.
echo   Keep the opened terminal windows running.
echo   To stop all services, run stop.bat or close the windows.
echo ============================================================
echo.
pause
