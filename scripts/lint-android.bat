@echo off
###########################################
# Android Lint
# Replicates android-lint job from .github/workflows/ci.yml
###########################################

setlocal enabledelayedexpansion

:: Project root
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
set "REPORT_DIR=%PROJECT_ROOT%\build\local-ci-reports\lint\android"

:: ANSI color codes
for /F %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"
set "RED=%ESC%[31m"
set "GREEN=%ESC%[32m"
set "YELLOW=%ESC%[33m"
set "BLUE=%ESC%[34m"
set "NC=%ESC%[0m"

:: Start timer
set "START_TIME=%time%"

echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|🔍 Android Lint                            ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

:: Create report directory
echo %BLUE%ℹ%NC% Creating report directory...
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

:: Change to project root
cd /d "%PROJECT_ROOT%"

:: Run Android lint
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Running Android Lint                      ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %BLUE%ℹ%NC% Running: gradlew.bat lintDebug

call gradlew.bat lintDebug > "%REPORT_DIR%\android-lint-output.log" 2>&1
set "LINT_EXIT_CODE=%ERRORLEVEL%"

if %LINT_EXIT_CODE% EQU 0 (
    echo %GREEN%✓%NC% Android lint completed
) else (
    echo %RED%✗%NC% Android lint failed
    set "LINT_EXIT_CODE=1"
)

:: Copy lint reports
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Collecting Lint Reports                   ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

echo %BLUE%ℹ%NC% Copying lint reports...
if not exist "%REPORT_DIR%\reports" mkdir "%REPORT_DIR%\reports"
if exist "app\build\reports\lint-results*" xcopy /E /I /Y "app\build\reports\lint-results*" "%REPORT_DIR%\reports\" >nul 2>&1

:: Find HTML report
set "LINT_HTML="
for /f "delims=" %%i in ('dir /s /b "%REPORT_DIR%\reports\lint-results-*.html" 2^>nul') do (
    set "LINT_HTML=%%i"
    goto :found_html
)
:found_html

:: Generate summary
echo. > "%REPORT_DIR%\android-lint-summary.txt"
echo ======================================== >> "%REPORT_DIR%\android-lint-summary.txt"
echo Android Lint Summary >> "%REPORT_DIR%\android-lint-summary.txt"
echo ======================================== >> "%REPORT_DIR%\android-lint-summary.txt"
if %LINT_EXIT_CODE% EQU 0 (
    echo Status: PASSED >> "%REPORT_DIR%\android-lint-summary.txt"
) else (
    echo Status: FAILED >> "%REPORT_DIR%\android-lint-summary.txt"
)
echo Timestamp: %date% %time% >> "%REPORT_DIR%\android-lint-summary.txt"
echo. >> "%REPORT_DIR%\android-lint-summary.txt"
echo Report Location: >> "%REPORT_DIR%\android-lint-summary.txt"
if defined LINT_HTML (
    echo - HTML: !LINT_HTML! >> "%REPORT_DIR%\android-lint-summary.txt"
)
echo - Log: %REPORT_DIR%\android-lint-output.log >> "%REPORT_DIR%\android-lint-summary.txt"

:: Display summary
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Android Lint Results                      ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

if defined LINT_HTML (
    echo %BLUE%ℹ%NC% HTML report: !LINT_HTML!
)

type "%REPORT_DIR%\android-lint-summary.txt"

echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Complete                                   ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%

exit /b %LINT_EXIT_CODE%
