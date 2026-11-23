@echo off
rem Temporary launcher for Eptal-Analyzer (based on L0p4Map, run from program folder).

rem Request administrator privileges if needed.
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator privileges...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
  exit /b
)

set "APP_DIR=%~dp0"
pushd "%APP_DIR%"

rem Check program entry point.
if not exist "main.py" (
  echo [Error] main.py not found in "%APP_DIR%"
  pause
  exit /b 1
)

rem Activate venv if it exists.
if exist "venv\Scripts\activate.bat" (
  call "venv\Scripts\activate.bat"
) else (
  echo [Warning] venv not found, using system Python.
  echo To prepare environment:
  echo   python -m venv venv
  echo   venv\Scripts\activate
  echo   pip install -r requirements.txt
  echo.
)

rem Run Eptal-Analyzer. Admin rights and Nmap/Npcap may be required for full functionality.
python main.py
set "EXIT_CODE=%ERRORLEVEL%"

popd

rem Pause on error so the message stays visible.
if not "%EXIT_CODE%"=="0" (
  echo.
  echo [Error] Eptal-Analyzer exited with code %EXIT_CODE%.
  pause
)

exit /b %EXIT_CODE%
