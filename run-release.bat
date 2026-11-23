@echo off
rem Release launcher for Eptal-Analyzer (no console window).

rem Request administrator privileges if needed.
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
  exit /b
)

set "APP_DIR=%~dp0"
pushd "%APP_DIR%"

rem Check program entry point.
if not exist "main.py" (
  exit /b 1
)

rem Activate venv if it exists.
if exist "venv\Scripts\activate.bat" (
  call "venv\Scripts\activate.bat"
)

rem Run Eptal-Analyzer without console window.
start "" pythonw.exe main.py
popd
exit /b 0
