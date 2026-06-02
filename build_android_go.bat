@echo off
setlocal enabledelayedexpansion

echo === Building Go client for Android (CGO) ===

set "PROJECT_ROOT=%~dp0"
set "GO_CLIENT_DIR=%PROJECT_ROOT%go_client"
set "ANDROID_JNILIBS=%PROJECT_ROOT%app\src\main\jniLibs"

:: 1. Find NDK Path
if defined ANDROID_HOME (
    set "SDK_PATH=%ANDROID_HOME%"
) else if defined ANDROID_SDK_ROOT (
    set "SDK_PATH=%ANDROID_SDK_ROOT%"
) else (
    set "SDK_PATH=C:\Users\YOUR_USERNAME_HERE\AppData\Local\Android\Sdk"
)
set "NDK_ROOT=%SDK_PATH%\ndk"

if not exist "%NDK_ROOT%" (
    echo Error: NDK folder not found at %NDK_ROOT%
    pause
    exit /b 1
)

:: Get latest NDK version
for /f "delims=" %%D in ('dir /b /ad /o-n "%NDK_ROOT%"') do (
    set "NDK_VER=%%D"
    goto :FoundNDK
)

:FoundNDK
if not defined NDK_VER (
    echo Error: No NDK versions found in %NDK_ROOT%
    pause
    exit /b 1
)
echo Using NDK: %NDK_VER%
set "TOOLCHAIN=%NDK_ROOT%\%NDK_VER%\toolchains\llvm\prebuilt\windows-x86_64\bin"
:: 2. Find Compilers (API 29+)
set "CC_PATH_ARM64=%TOOLCHAIN%\aarch64-linux-android29-clang.cmd"
if not exist "%CC_PATH_ARM64%" (
    set "CC_PATH_ARM64=%TOOLCHAIN%\aarch64-linux-android30-clang.cmd"
)

set "CC_PATH_ARM32=%TOOLCHAIN%\armv7a-linux-androideabi29-clang.cmd"
if not exist "%CC_PATH_ARM32%" (
    set "CC_PATH_ARM32=%TOOLCHAIN%\armv7a-linux-androideabi30-clang.cmd"
)

set "CC_PATH_X86_64=%TOOLCHAIN%\x86_64-linux-android29-clang.cmd"
if not exist "%CC_PATH_X86_64%" (
    set "CC_PATH_X86_64=%TOOLCHAIN%\x86_64-linux-android30-clang.cmd"
)

if not exist "%CC_PATH_ARM64%" (
    echo Error: Clang compiler for arm64 not found in %TOOLCHAIN%
    pause
    exit /b 1
)

if not exist "%CC_PATH_ARM32%" (
    echo Error: Clang compiler for arm32 not found in %TOOLCHAIN%
    pause
    exit /b 1
)

if not exist "%CC_PATH_X86_64%" (
    echo Error: Clang compiler for x86_64 not found in %TOOLCHAIN%
    pause
    exit /b 1
)

:: Common build variables
set "GOOS=android"
set "CGO_ENABLED=1"

echo Checking Go modules...
cd /d "%GO_CLIENT_DIR%"
go mod download
if %errorlevel% neq 0 (
    echo go mod download FAILED!
    pause
    exit /b 1
)

:: Android source-set output folders. Build goes directly here, no root jniLibs copy step.
if not exist "%ANDROID_JNILIBS%\arm64-v8a" mkdir "%ANDROID_JNILIBS%\arm64-v8a" 2>nul
if not exist "%ANDROID_JNILIBS%\armeabi-v7a" mkdir "%ANDROID_JNILIBS%\armeabi-v7a" 2>nul
if not exist "%ANDROID_JNILIBS%\x86_64" mkdir "%ANDROID_JNILIBS%\x86_64" 2>nul

:: 3. Build arm64-v8a (aarch64)
echo.
echo [1/3] Building arm64-v8a (aarch64)...
set "GOARCH=arm64"
set "GOARM="
set "CC=%CC_PATH_ARM64%"
echo Using Compiler: %CC%

go build -ldflags="-s -w -checklinkname=0" -trimpath -o "%ANDROID_JNILIBS%\arm64-v8a\libclient.so" .

if %errorlevel% neq 0 (
    echo BUILD arm64 FAILED!
    pause
    exit /b 1
)
echo arm64-v8a: OK

:: 4. Build armeabi-v7a (arm32)
echo.
echo [2/3] Building armeabi-v7a (arm32 v7)...
set "GOARCH=arm"
set "GOARM=7"
set "CC=%CC_PATH_ARM32%"
echo Using Compiler: %CC%

go build -ldflags="-s -w -checklinkname=0" -trimpath -o "%ANDROID_JNILIBS%\armeabi-v7a\libclient.so" .

if %errorlevel% neq 0 (
    echo BUILD arm32 FAILED!
    pause
    exit /b 1
)
echo armeabi-v7a: OK

:: 5. Build x86_64
echo.
echo [3/3] Building x86_64...
set "GOARCH=amd64"
set "GOARM="
set "CC=%CC_PATH_X86_64%"
echo Using Compiler: %CC%

go build -ldflags="-s -w -checklinkname=0" -trimpath -o "%ANDROID_JNILIBS%\x86_64\libclient.so" .

if %errorlevel% neq 0 (
    echo BUILD x86_64 FAILED!
    pause
    exit /b 1
)
echo x86_64: OK

echo.
echo === BUILD SUCCESS ===
for %%F in ("%ANDROID_JNILIBS%\arm64-v8a\libclient.so") do echo   arm64-v8a:   app\src\main\jniLibs\arm64-v8a\libclient.so   [%%~zF bytes]
for %%F in ("%ANDROID_JNILIBS%\armeabi-v7a\libclient.so") do echo   armeabi-v7a: app\src\main\jniLibs\armeabi-v7a\libclient.so [%%~zF bytes]
for %%F in ("%ANDROID_JNILIBS%\x86_64\libclient.so") do echo   x86_64:      app\src\main\jniLibs\x86_64\libclient.so      [%%~zF bytes]
echo.
echo === Libraries updated. Now build APK. ===
pause
