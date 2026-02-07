@echo off
:: ###########################################
:: Combined Lint Checks
:: Runs ktlint and Android lint
:: ###########################################

setlocal enabledelayedexpansion

:: ANSI color codes
for /F %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"
set "BLUE=%ESC%[34m"
set "GREEN=%ESC%[32m"
set "RED=%ESC%[31m"
set "NC=%ESC%[0m"

echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|🔍 Combined Lint Checks                    ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%

set "KTLINT_EXIT_CODE=0"
set "ANDROID_LINT_EXIT_CODE=0"

:: Run ktlint
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|1/2: ktlint                                ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

call "%~dp0lint-ktlint.bat"
if errorlevel 1 (
    set "KTLINT_EXIT_CODE=1"
    echo %RED%✗%NC% ktlint failed
) else (
    echo %GREEN%✓%NC% ktlint passed
)

:: Run Android lint
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|2/2: Android Lint                          ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

call "%~dp0lint-android.bat"
if errorlevel 1 (
    set "ANDROID_LINT_EXIT_CODE=1"
    echo %RED%✗%NC% Android lint failed
) else (
    echo %GREEN%✓%NC% Android lint passed
)

:: Final summary
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Lint Summary                               ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

if %KTLINT_EXIT_CODE% EQU 0 if %ANDROID_LINT_EXIT_CODE% EQU 0 (
    echo %GREEN%✓ All lint checks passed%NC%
    exit /b 0
) else (
    echo %RED%✗ Some lint checks failed:%NC%
    if %KTLINT_EXIT_CODE% NEQ 0 echo   - ktlint
    if %ANDROID_LINT_EXIT_CODE% NEQ 0 echo   - Android lint
    exit /b 1
)
