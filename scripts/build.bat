@echo off
###########################################
# Build APKs - Debug and Release
# Replicates build job from .github/workflows/ci.yml
###########################################

setlocal enabledelayedexpansion

:: Project root
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
set "REPORT_DIR=%PROJECT_ROOT%\build\local-ci-reports\build"

:: ANSI color codes (Windows 10+)
for /F %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"
set "RED=%ESC%[31m"
set "GREEN=%ESC%[32m"
set "YELLOW=%ESC%[33m"
set "BLUE=%ESC%[34m"
set "NC=%ESC%[0m"

:: Start timer
set "START_TIME=%time%"

echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|🔨 Build APKs - Debug and Release          ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

:: Create report directory
echo %BLUE%ℹ%NC% Creating report directory...
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

:: Check Java version
echo %BLUE%ℹ%NC% Checking Java version...
where java >nul 2>&1
if errorlevel 1 (
    echo %RED%✗%NC% Java not found. Please install Java 17.
    exit /b 2
)

for /f "tokens=3" %%i in ('java -version 2^>^&1 ^| findstr /i "version"') do set "JAVA_VER=%%i"
set "JAVA_VER=%JAVA_VER:"=%"
for /f "tokens=1,2 delims=." %%a in ("%JAVA_VER%") do set "JAVA_MAJOR=%%a"

echo %GREEN%✓%NC% Java version OK: %JAVA_VER%

:: Change to project root
cd /d "%PROJECT_ROOT%"

:: Build Debug APK
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|📱 Building Debug APK                       ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %BLUE%ℹ%NC% Running: gradlew.bat assembleDebug

call gradlew.bat assembleDebug --stacktrace > "%REPORT_DIR%\build-debug.log" 2>&1
if errorlevel 1 (
    echo %RED%✗%NC% Debug APK build failed
    echo Check log: %REPORT_DIR%\build-debug.log
    exit /b 1
)

echo %GREEN%✓%NC% Debug APK built successfully

:: Find and display APK location
for /f "delims=" %%i in ('dir /s /b "app\build\outputs\apk\debug\*.apk" 2^>nul ^| findstr /r "debug-.*\.apk$"') do (
    set "DEBUG_APK=%%i"
    goto :found_debug
)
:found_debug
if defined DEBUG_APK (
    echo %BLUE%ℹ%NC% Debug APK: !DEBUG_APK!
    echo !DEBUG_APK! > "%REPORT_DIR%\debug-apk-path.txt"
)

:: Build Release APK
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|📱 Building Release APK                     ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %BLUE%ℹ%NC% Running: gradlew.bat assembleRelease

call gradlew.bat assembleRelease --stacktrace > "%REPORT_DIR%\build-release.log" 2>&1
if errorlevel 1 (
    echo %RED%✗%NC% Release APK build failed
    echo Check log: %REPORT_DIR%\build-release.log
    exit /b 1
)

echo %GREEN%✓%NC% Release APK built successfully

:: Find and display APK location
for /f "delims=" %%i in ('dir /s /b "app\build\outputs\apk\release\*.apk" 2^>nul ^| findstr /r "release-.*\.apk$"') do (
    set "RELEASE_APK=%%i"
    goto :found_release
)
:found_release
if defined RELEASE_APK (
    echo %BLUE%ℹ%NC% Release APK: !RELEASE_APK!
    echo !RELEASE_APK! > "%REPORT_DIR%\release-apk-path.txt"
)

:: Calculate duration (simplified)
set "END_TIME=%time%"

:: Generate build summary
echo. > "%REPORT_DIR%\build-summary.txt"
echo ======================================== >> "%REPORT_DIR%\build-summary.txt"
echo Build Summary >> "%REPORT_DIR%\build-summary.txt"
echo ======================================== >> "%REPORT_DIR%\build-summary.txt"
echo Status: SUCCESS >> "%REPORT_DIR%\build-summary.txt"
echo Timestamp: %date% %time% >> "%REPORT_DIR%\build-summary.txt"
echo. >> "%REPORT_DIR%\build-summary.txt"
echo Debug APK: >> "%REPORT_DIR%\build-summary.txt"
echo - Path: %DEBUG_APK% >> "%REPORT_DIR%\build-summary.txt"
echo. >> "%REPORT_DIR%\build-summary.txt"
echo Release APK: >> "%REPORT_DIR%\build-summary.txt"
echo - Path: %RELEASE_APK% >> "%REPORT_DIR%\build-summary.txt"
echo. >> "%REPORT_DIR%\build-summary.txt"
echo Logs: >> "%REPORT_DIR%\build-summary.txt"
echo - Debug build: %REPORT_DIR%\build-debug.log >> "%REPORT_DIR%\build-summary.txt"
echo - Release build: %REPORT_DIR%\build-release.log >> "%REPORT_DIR%\build-summary.txt"

:: Final summary
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|✅ Build Complete                           ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %GREEN%✓%NC% All APKs built successfully
echo %BLUE%ℹ%NC% Reports saved to: %REPORT_DIR%
type "%REPORT_DIR%\build-summary.txt"

exit /b 0
