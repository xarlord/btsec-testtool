@echo off
:: ###########################################
:: ktlint - Kotlin Code Style Linter
:: Replicates ktlint job from .github/workflows/ci.yml
:: ###########################################

setlocal enabledelayedexpansion

:: Project root
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
set "REPORT_DIR=%PROJECT_ROOT%\build\local-ci-reports\lint\ktlint"

:: Configuration
set "KTLINT_VERSION=1.0.1"
set "KTLINT_URL=https://github.com/pinterest/ktlint/releases/download/%KTLINT_VERSION%/ktlint.jar"
set "KTLINT_BIN=%SCRIPT_DIR%\ktlint.jar"

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
echo %BLUE%^|🔍 ktlint - Kotlin Code Style             ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

:: Create report directory
echo %BLUE%ℹ%NC% Creating report directory...
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

:: Change to project root
cd /d "%PROJECT_ROOT%"

:: Download ktlint if not present
if not exist "%KTLINT_BIN%" (
    echo %BLUE%ℹ%NC% Downloading ktlint %KTLINT_VERSION%...

    :: Try curl
    where curl >nul 2>&1
    if %errorlevel% equ 0 (
        curl -sSL "%KTLINT_URL%" -o "%KTLINT_BIN%"
    ) else (
        :: Try wget
        where wget >nul 2>&1
        if %errorlevel% equ 0 (
            wget -q "%KTLINT_URL%" -O "%KTLINT_BIN%"
        ) else (
            :: Use PowerShell (always available on Windows)
            echo %BLUE%ℹ%NC% Using PowerShell to download...
            powershell -Command "Invoke-WebRequest -Uri '%KTLINT_URL%' -OutFile '%KTLINT_BIN%'"
        )
    )

    if not exist "%KTLINT_BIN%" (
        echo %RED%✗%NC% Failed to download ktlint
        echo Please download ktlint manually:
        echo   %KTLINT_URL%
        echo   Place it in: %KTLINT_BIN%
        exit /b 2
    )

    echo %GREEN%✓%NC% ktlint downloaded
)

echo %BLUE%ℹ%NC% Using ktlint: %KTLINT_BIN%

:: Run ktlint
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Running ktlint                            ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %BLUE%ℹ%NC% Scanning Kotlin files...

java -jar "%KTLINT_BIN%" --reporter=checkstyle,output="%REPORT_DIR%\ktlint-report.xml" "**/*.kt" "**/*.kts" > "%REPORT_DIR%\ktlint-output.log" 2>&1
set "KTLINT_EXIT_CODE=%ERRORLEVEL%"

if %KTLINT_EXIT_CODE% EQU 0 (
    echo %GREEN%✓%NC% No ktlint issues found
) else (
    echo %RED%✗%NC% ktlint found issues
    set "KTLINT_EXIT_CODE=1"
)

:: Parse and display results
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|ktlint Results                            ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

if exist "%REPORT_DIR%\ktlint-report.xml" (
    findstr /C:"<error " "%REPORT_DIR%\ktlint-report.xml" >nul 2>&1
    if errorlevel 1 (
        echo %GREEN%✓%NC% No violations found
    ) else (
        echo %RED%✗%NC% Violations found - see report
    )
) else (
    echo %YELLOW%⚠%NC% No ktlint report generated
)

:: Generate summary
echo. > "%REPORT_DIR%\ktlint-summary.txt"
echo ======================================== >> "%REPORT_DIR%\ktlint-summary.txt"
echo ktlint Summary >> "%REPORT_DIR%\ktlint-summary.txt"
echo ======================================== >> "%REPORT_DIR%\ktlint-summary.txt"
if %KTLINT_EXIT_CODE% EQU 0 (
    echo Status: PASSED >> "%REPORT_DIR%\ktlint-summary.txt"
) else (
    echo Status: FAILED >> "%REPORT_DIR%\ktlint-summary.txt"
)
echo Timestamp: %date% %time% >> "%REPORT_DIR%\ktlint-summary.txt"
echo. >> "%REPORT_DIR%\ktlint-summary.txt"
echo Report Location: >> "%REPORT_DIR%\ktlint-summary.txt"
echo - XML: %REPORT_DIR%\ktlint-report.xml >> "%REPORT_DIR%\ktlint-summary.txt"
echo - Log: %REPORT_DIR%\ktlint-output.log >> "%REPORT_DIR%\ktlint-summary.txt"

type "%REPORT_DIR%\ktlint-summary.txt"

echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Complete                                   ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%

exit /b %KTLINT_EXIT_CODE%
