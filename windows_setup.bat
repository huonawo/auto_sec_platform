@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

echo ============================================================
echo   AutoSec Platform - Windows GUI 一键安装脚本
echo ============================================================
echo.

:: -----------------------------------------------------------
:: 1. 检查 Python 是否已安装
:: -----------------------------------------------------------
echo [1/5] 检查 Python 环境...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到 Python，请先安装 Python 3.10 或更高版本。
    echo        下载地址: https://www.python.org/downloads/
    echo        安装时请勾选 "Add Python to PATH"。
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo        Python 版本: %PYVER%

:: 检查 Python 版本是否 >= 3.10
for /f "tokens=1,2 delims=." %%a in ("%PYVER%") do (
    if %%a LSS 3 (
        echo [错误] Python 版本过低，需要 3.10+，当前为 %PYVER%
        pause
        exit /b 1
    )
    if %%a EQU 3 (
        if %%b LSS 10 (
            echo [错误] Python 版本过低，需要 3.10+，当前为 %PYVER%
            pause
            exit /b 1
        )
    )
)
echo        Python 版本检查通过。
echo.

:: -----------------------------------------------------------
:: 2. 升级 pip
:: -----------------------------------------------------------
echo [2/5] 升级 pip...
python -m pip install --upgrade pip --quiet
if %errorlevel% neq 0 (
    echo [警告] pip 升级失败，继续使用当前版本...
)
echo        pip 升级完成。
echo.

:: -----------------------------------------------------------
:: 3. 安装 Python 依赖
:: -----------------------------------------------------------
echo [3/5] 安装 Python 依赖包...
echo        - PyQt5         (GUI 框架)
echo        - requests      (HTTP 客户端)
echo.

pip install PyQt5 requests --quiet
if %errorlevel% neq 0 (
    echo [错误] 依赖安装失败，请检查网络连接或 pip 配置。
    pause
    exit /b 1
)
echo        依赖安装完成。
echo.

:: -----------------------------------------------------------
:: 4. 验证安装
:: -----------------------------------------------------------
echo [4/5] 验证安装...
python -c "import PyQt5; print('        PyQt5     ' + PyQt5.QtCore.PYQT_VERSION_STR)" 2>nul
if %errorlevel% neq 0 (
    echo [错误] PyQt5 导入失败。
    pause
    exit /b 1
)

python -c "import requests; print('        requests  ' + requests.__version__)" 2>nul
if %errorlevel% neq 0 (
    echo [错误] requests 导入失败。
    pause
    exit /b 1
)
echo        所有依赖验证通过。
echo.

:: -----------------------------------------------------------
:: 5. 创建启动脚本
:: -----------------------------------------------------------
echo [5/5] 创建快捷启动脚本...

(
echo @echo off
echo chcp 65001 ^>nul 2^>^&1
echo echo 启动 AutoSec Platform GUI...
echo echo 请确保后端服务已启动 (默认地址: http://localhost:8000^)
echo echo.
echo cd /d "%%~dp0"
echo python frontend\gui\main_gui.py
echo pause
) > "%~dp0start_gui.bat"

echo        已创建 start_gui.bat
echo.

:: -----------------------------------------------------------
:: 完成
:: -----------------------------------------------------------
echo ============================================================
echo   安装完成！
echo ============================================================
echo.
echo   后续步骤:
echo   1. 启动后端服务 (在 Linux/Docker 环境中):
echo      docker-compose up -d
echo   2. 在 Windows 上运行 GUI:
echo      双击 start_gui.bat 或执行:
echo      python frontend\gui\main_gui.py
echo.
echo   注意: GUI 需要后端 API 服务运行在 http://localhost:8000
echo         可在 GUI 设置中修改 API 地址。
echo ============================================================
echo.
pause
