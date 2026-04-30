@echo off
setlocal
cd /d "%~dp0\.."

set "PYTHON="

where python >nul 2>nul
if not errorlevel 1 (
    set "PYTHON=python"
)

if not defined PYTHON (
    where py >nul 2>nul
    if not errorlevel 1 (
        py -3 --version >nul 2>nul
        if not errorlevel 1 (
            set "PYTHON=py -3"
        )
    )
)

if not defined PYTHON (
    echo Python was not found on PATH.
    echo Install Python 3.10+ from https://www.python.org/downloads/
    echo Then run this script again.
    exit /b 1
)

%PYTHON% -m unittest discover -s tests -v
if %errorlevel% neq 0 exit /b %errorlevel%

%PYTHON% -m compileall backend frontend plugins tests
if %errorlevel% neq 0 exit /b %errorlevel%
