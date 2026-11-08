@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================================
echo   MemGuard 打包为单文件 exe
echo   说明：L2 清理备用列表需要管理员权限，请右键 exe 选择
echo         「以管理员身份运行」；普通权限下 L1/L3 与全部监控可用。
echo ============================================================

set "PYEXE=py -3"
py -3 -c "import tkinter" 1>nul 2>nul
if errorlevel 1 set "PYEXE=python"
echo 使用解释器：%PYEXE%（图形界面必须带 tkinter）

echo [1/3] 检查 PyInstaller ...
%PYEXE% -c "import PyInstaller" 1>nul 2>nul
if errorlevel 1 (
  echo     未安装，正在安装 PyInstaller ...
  %PYEXE% -m pip install --disable-pip-version-check pyinstaller
)

echo [2/3] 安装可选托盘依赖 ...
%PYEXE% -m pip install --disable-pip-version-check -r requirements.txt

echo [3/3] 开始打包 ...
%PYEXE% -m PyInstaller --noconfirm --clean --onefile --noconsole --name MemGuard --hidden-import pystray --hidden-import PIL.Image --hidden-import PIL.ImageDraw --add-data "tests\selftest.py;tests" --add-data "tests\full_matrix.py;tests" --add-data "main.py;." --add-data "memguard\ui.py;memguard" main.py

if errorlevel 1 (
  echo.
  echo 打包失败，请查看上面的 PyInstaller 输出。
  pause
  exit /b 1
)
echo.
echo 打包完成：dist\MemGuard.exe
echo 自测：MemGuard.exe --selftest  /  MemGuard.exe --fulltest（需控制台查看输出）
echo 配置文件与日志会写到 %%LOCALAPPDATA%%\MemGuard
pause
