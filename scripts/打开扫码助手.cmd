@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
if exist "%~dp0python\pythonw.exe" (
  start "" "%~dp0python\pythonw.exe" "%~dp0watch_verification.py" --open-now
  exit /b
)
where py >nul 2>nul
if not errorlevel 1 (
  start "" /b py -3 "%~dp0watch_verification.py" --open-now
  exit /b
)
where python >nul 2>nul
if not errorlevel 1 (
  start "" /b python "%~dp0watch_verification.py" --open-now
  exit /b
)
echo 需要 Python 3.10 或更新版本，或使用附带便携 Python 的扫码助手压缩包。
pause
