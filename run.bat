@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================================
echo   MemGuard 内存锚点管家 - 源码运行
echo   常用参数：
echo     run.bat --selftest    运行安全自测（47 项，只读）
echo     run.bat --fulltest    运行全工况/全参数验证（332 项矩阵，只读）
echo     run.bat --collect     只打印一次内存/显存快照
echo     run.bat --no-auto     本次不启动自动巡检
echo     run.bat --no-tray     本次不加载托盘
echo ============================================================
set "PYEXE=py -3"
py -3 -c "import tkinter" 1>nul 2>nul
if errorlevel 1 set "PYEXE=python"
echo   解释器：%PYEXE%
%PYEXE% main.py %*
if errorlevel 1 (
  echo.
  echo 程序返回了错误码，上面的输出即为原因。
  pause
)
