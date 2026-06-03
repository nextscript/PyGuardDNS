@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo Requesting administrator rights for DNS port 53...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set LOCALDNSGUARD_WEB_HOST=0.0.0.0
set LOCALDNSGUARD_WEB_PORT=8080
set LOCALDNSGUARD_DNS_HOST=0.0.0.0
set LOCALDNSGUARD_DNS_PORT=53
set LOCALDNSGUARD_STRICT_DNS_PORT=1
set LOCALDNSGUARD_MAX_DNS_WORKERS=48
set LOCALDNSGUARD_MAX_UPSTREAM_WORKERS=8

set PYTHON_EXE=
call :find_python
if not defined PYTHON_EXE (
  call :install_python
  call :find_python
)
if not defined PYTHON_EXE (
  echo.
  echo Python could not be installed or found automatically.
  echo Please install Python 3.11+ and then start this script again:
  echo https://www.python.org/downloads/
  pause
  exit /b 1
)
call :setup_venv
if errorlevel 1 (
  echo.
  echo Python environment could not be created.
  pause
  exit /b 1
)

echo Starting LocalDNSGuard...
echo Web UI: http://127.0.0.1:%LOCALDNSGUARD_WEB_PORT%
echo DNS:    %LOCALDNSGUARD_DNS_HOST%:%LOCALDNSGUARD_DNS_PORT% UDP/TCP
echo.
echo Note: Port 53 often requires administrator rights on Windows.
echo If port 53 is already in use, the app exits instead of silently running DNS on the wrong port.
echo Python: %PYTHON_EXE%
echo.

ipconfig /flushdns >nul 2>&1

"%PYTHON_EXE%" -m pip --version >nul 2>&1
if errorlevel 1 (
  echo Installing pip...
  "%PYTHON_EXE%" -m ensurepip --upgrade
)

echo Checking Python requirements...
"%PYTHON_EXE%" -m pip install -r requirements.txt --disable-pip-version-check
if errorlevel 1 (
  echo FAILED: Python requirements could not be installed.
  pause
  exit /b 1
)
echo All Python requirements are installed.
echo.
echo Server console is active. Commands: restart, stop, status, cache clear, update blocklist
echo.
"%PYTHON_EXE%" .\app.py 2>>server.err.log

set EXIT_CODE=%errorlevel%
if not "%EXIT_CODE%"=="0" (
  for /f %%a in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "CRASH_STAMP=%%a"
  if not defined CRASH_STAMP set "CRASH_STAMP=fallback"
  set "CRASH_FILE=crash_!CRASH_STAMP!.txt"
  set "CRASH_LATEST=crash_timestamp.txt"
  (
    echo LocalDNSGuard process exited unexpectedly
    echo timestamp: %date% %time%
    echo exit_code: %EXIT_CODE%
    echo command: %PYTHON_EXE% .\app.py
    echo.
  ) > "!CRASH_FILE!"
  if exist startup.log (
    >> "!CRASH_FILE!" echo --- startup.log tail ---
    powershell -NoProfile -Command "Get-Content '.\startup.log' -Tail 80" >> "!CRASH_FILE!"
  )
  if exist server.err.log (
    >> "!CRASH_FILE!" echo.
    >> "!CRASH_FILE!" echo --- server.err.log tail ---
    powershell -NoProfile -Command "Get-Content '.\server.err.log' -Tail 120" >> "!CRASH_FILE!"
  )
  if exist fatal-python.log (
    >> "!CRASH_FILE!" echo.
    >> "!CRASH_FILE!" echo --- fatal-python.log tail ---
    powershell -NoProfile -Command "Get-Content '.\fatal-python.log' -Tail 120" >> "!CRASH_FILE!"
  )
  copy /Y "!CRASH_FILE!" "!CRASH_LATEST!" >nul 2>&1
  echo.
  echo Crash report written: !CRASH_FILE!
  echo Latest crash report: !CRASH_LATEST!
)

pause
exit /b %EXIT_CODE%

:find_python
if defined PYTHON_EXE exit /b 0
for /f "delims=" %%P in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do (
  set "PYTHON_EXE=%%P"
  exit /b 0
)
for /f "delims=" %%P in ('python -c "import sys; print(sys.executable)" 2^>nul') do (
  set "PYTHON_EXE=%%P"
  exit /b 0
)
for /f "delims=" %%P in ('python3 -c "import sys; print(sys.executable)" 2^>nul') do (
  set "PYTHON_EXE=%%P"
  exit /b 0
)
for %%P in (
  "%ProgramFiles%\Python313\python.exe"
  "%ProgramFiles%\Python312\python.exe"
  "%ProgramFiles%\Python311\python.exe"
  "%LocalAppData%\Programs\Python\Python313\python.exe"
  "%LocalAppData%\Programs\Python\Python312\python.exe"
  "%LocalAppData%\Programs\Python\Python311\python.exe"
) do (
  if exist "%%~P" (
    set "PYTHON_EXE=%%~P"
    exit /b 0
  )
)
exit /b 1

:install_python
echo Python was not found. Trying installation through winget...
where winget >nul 2>&1
if errorlevel 1 (
  echo winget was not found.
  exit /b 1
)
winget install --id Python.Python.3.13 -e --source winget --accept-package-agreements --accept-source-agreements
exit /b %errorlevel%

:setup_venv
set "BASE_PYTHON_EXE=%PYTHON_EXE%"
if not exist ".venv\Scripts\python.exe" (
  echo Creating local Python environment...
  "%BASE_PYTHON_EXE%" -m venv .venv
)
if exist ".venv\Scripts\python.exe" (
  set "PYTHON_EXE=%CD%\.venv\Scripts\python.exe"
  exit /b 0
)
set "PYTHON_EXE=%BASE_PYTHON_EXE%"
exit /b 1
