@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

echo ============================================================
echo   AutoSec Platform - Windows setup
echo ============================================================
echo.

echo [1/5] Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found.
    echo         Install Python 3.10+ from https://www.python.org/downloads/
    echo         Enable "Add Python to PATH" during installation.
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo        Python version: %PYVER%
echo.

echo [2/5] Upgrading pip...
python -m pip install --upgrade pip --quiet
if %errorlevel% neq 0 (
    echo [WARN] pip upgrade failed; continuing with current pip.
)
echo.

echo [3/5] Installing Python dependencies...
python -m pip install PyQt5 requests --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install GUI dependencies.
    pause
    exit /b 1
)

python -m pip install -r backend\requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install backend dependencies.
    pause
    exit /b 1
)
echo.

echo [4/5] Verifying imports...
python -c "import PyQt5; import requests; import fastapi; import celery; import redis; print('        imports OK')" 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Dependency import verification failed.
    pause
    exit /b 1
)
echo.

echo [5/5] Creating local config and launchers...
if not exist "%~dp0frontend\gui\config.json" (
    copy "%~dp0frontend\gui\config.example.json" "%~dp0frontend\gui\config.json" >nul 2>&1
    echo        Created frontend\gui\config.json
)

(
echo @echo off
echo chcp 65001 ^>nul 2^>^&1
echo cd /d "%%~dp0"
echo echo Starting AutoSec Platform GUI...
echo echo Ensure the backend API is running at the configured URL.
echo python frontend\gui\main_gui.py
echo pause
) > "%~dp0start_gui.bat"

echo        Created start_gui.bat
echo.

echo ============================================================
echo   Setup complete
echo ============================================================
echo.
echo Next steps:
echo   1. Run preflight:
echo      powershell -ExecutionPolicy Bypass -File scripts\preflight.ps1
echo   2. Start Docker services:
echo      docker compose up -d
echo   3. Check Docker runtime health:
echo      powershell -ExecutionPolicy Bypass -File scripts\docker_health.ps1
echo   4. Or start the backend locally:
echo      scripts\run_backend_local.bat
echo   5. Start the GUI:
echo      start_gui.bat
echo   6. Run tests:
echo      scripts\run_tests.bat
echo.
pause
