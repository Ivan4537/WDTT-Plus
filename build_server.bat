@echo off
echo === Building server for Linux AMD64 ===
set GOOS=linux
set GOARCH=amd64
set CGO_ENABLED=0
go build -ldflags="-s -w" -o server server.go
if %errorlevel% neq 0 (
    echo FAILED: server
    pause
    exit /b 1
)
echo OK: server

:: 2. Move to assets for Android deployment
if not exist "app\src\main\assets" mkdir "app\src\main\assets"
move /Y server app\src\main\assets\server

echo.
echo OK: Server moved to app\src\main\assets\server
echo.
pause