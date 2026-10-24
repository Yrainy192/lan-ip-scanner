@echo off
setlocal
set "SCRIPT=%~dp0LanScanner.ps1"
if not exist "%SCRIPT%" (
    echo LanScanner.ps1 was not found.
    pause
    exit /b 1
)
set "RUNNER=powershell.exe"
where pwsh.exe >nul 2>nul
if not errorlevel 1 set "RUNNER=pwsh.exe"
start "" "%RUNNER%" -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "%SCRIPT%"
endlocal
