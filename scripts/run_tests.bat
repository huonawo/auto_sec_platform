@echo off
setlocal
cd /d "%~dp0\.."

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Python was not found on PATH.
    echo Install Python 3.10+ or run the equivalent command with your Python executable:
    echo python -m unittest discover -s tests -v
    exit /b 1
)

python -m unittest discover -s tests -v
python -m compileall backend frontend plugins tests
