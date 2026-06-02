@echo off
setlocal enabledelayedexpansion

echo === WDTT APK Build Script ===
echo === Output: 4 APKs (universal, arm64-v8a, armeabi-v7a, x86_64) ===
echo.

:: 1. Verify .so files exist for all architectures
set "MISSING=0"
if not exist "app\src\main\jniLibs\arm64-v8a\libclient.so" (
    echo ERROR: arm64-v8a .so not found!
    set "MISSING=1"
)
if not exist "app\src\main\jniLibs\armeabi-v7a\libclient.so" (
    echo ERROR: armeabi-v7a .so not found!
    set "MISSING=1"
)
if not exist "app\src\main\jniLibs\x86_64\libclient.so" (
    echo ERROR: x86_64 .so not found!
    set "MISSING=1"
)
if "%MISSING%"=="1" (
    echo.
    echo Run build_android_go.bat first to build all native libraries!
    pause
    exit /b 1
)

:: 2. Skipping clean for faster incremental builds
echo Incremental build...

:: 3. Build release APKs (ABI splits produce 4 APKs)
echo Building release APKs...
call gradlew assembleRelease --no-daemon

if %errorlevel% neq 0 (
    echo.
    echo BUILD FAILED! Please check the errors above.
    pause
    exit /b 1
)

:: 4. Create release directory
if not exist "app\release" mkdir "app\release"

:: 5. Copy and rename all APK variants
echo.
echo Copying APKs to release folder...

set "APK_DIR=app\build\outputs\apk\release"

:: Universal APK (all architectures)
if exist "%APK_DIR%\app-universal-release.apk" (
    copy /Y "%APK_DIR%\app-universal-release.apk" "app\release\WDTT-universal.apk" >nul
    for %%F in ("app\release\WDTT-universal.apk") do echo   [OK] WDTT-universal.apk  [%%~zF bytes]
) else (
    echo   [!!] Universal APK not found
)

:: arm64-v8a
if exist "%APK_DIR%\app-arm64-v8a-release.apk" (
    copy /Y "%APK_DIR%\app-arm64-v8a-release.apk" "app\release\WDTT-arm64-v8a.apk" >nul
    for %%F in ("app\release\WDTT-arm64-v8a.apk") do echo   [OK] WDTT-arm64-v8a.apk  [%%~zF bytes]
) else (
    echo   [!!] arm64-v8a APK not found
)

:: armeabi-v7a
if exist "%APK_DIR%\app-armeabi-v7a-release.apk" (
    copy /Y "%APK_DIR%\app-armeabi-v7a-release.apk" "app\release\WDTT-armeabi-v7a.apk" >nul
    for %%F in ("app\release\WDTT-armeabi-v7a.apk") do echo   [OK] WDTT-armeabi-v7a.apk  [%%~zF bytes]
) else (
    echo   [!!] armeabi-v7a APK not found
)

:: x86_64
if exist "%APK_DIR%\app-x86_64-release.apk" (
    copy /Y "%APK_DIR%\app-x86_64-release.apk" "app\release\WDTT-x86_64.apk" >nul
    for %%F in ("app\release\WDTT-x86_64.apk") do echo   [OK] WDTT-x86_64.apk  [%%~zF bytes]
) else (
    echo   [!!] x86_64 APK not found
)

echo.
echo === DONE ===
echo Output directory: app\release\
echo.
echo   WDTT-universal.apk    - all architectures in one APK
echo   WDTT-arm64-v8a.apk    - 64-bit ARM only
echo   WDTT-armeabi-v7a.apk  - 32-bit ARM only
echo   WDTT-x86_64.apk       - x86_64 only
echo.
pause
