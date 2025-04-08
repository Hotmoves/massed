@echo off
set /p port="Enter the local port number to kill (e.g., 3002): "
echo Searching for process using port %port%...

:: Find the process using the specified port
for /f "tokens=5 delims= " %%a in ('netstat -aon ^| findstr :%port%.*LISTENING') do (
    set pid=%%a
)

:: Check if a PID was found
if not defined pid (
    echo No process found using port %port%.
    pause
    exit /b
)

:: Kill the process using the PID
echo Found process with PID %pid%. Terminating...
taskkill /PID %pid% /F

:: Verify the port is free
netstat -aon | findstr :%port%.*LISTENING >nul
if errorlevel 1 (
    echo Process on port %port% has been terminated successfully.
) else (
    echo Failed to terminate process on port %port%.
)

pause