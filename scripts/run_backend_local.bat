@echo off
setlocal
cd /d "%~dp0\.."

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Python was not found on PATH.
    echo Install Python 3.10+ before running the local backend.
    exit /b 1
)

set AUTOSEC_OUTPUT_DIR=%CD%\output
cd backend
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
