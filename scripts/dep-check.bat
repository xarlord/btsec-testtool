@echo off
###########################################
# OWASP Dependency Check
# Replicates dependency-check job from .github/workflows/ci.yml
###########################################

setlocal enabledelayedexpansion

:: Project root
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
set "REPORT_DIR=%PROJECT_ROOT%\build\local-ci-reports\dependency-check"

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
echo %BLUE%^|🔍 OWASP Dependency Check                 ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

:: Create report directory
echo %BLUE%ℹ%NC% Creating report directory...
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

:: Change to project root
cd /d "%PROJECT_ROOT%"

:: Run OWASP dependency check
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Running Dependency Vulnerability Scan     ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %BLUE%ℹ%NC% Running: gradlew.bat dependencyCheckAnalyze

call gradlew.bat dependencyCheckAnalyze > "%REPORT_DIR%\dep-check-output.log" 2>&1
set "DEP_EXIT_CODE=%ERRORLEVEL%"

if %DEP_EXIT_CODE% EQU 0 (
    echo %GREEN%✓%NC% Dependency check completed

    :: Find and copy report
    for /f "delims=" %%i in ('dir /s /b "app\build\reports\dependency-check-report.html" 2^>nul') do (
        copy "%%i" "%REPORT_DIR%\" >nul 2>&1
        set "DEP_REPORT=%%i"
        goto :found_report
    )
    :found_report
    if defined DEP_REPORT (
        echo %BLUE%ℹ%NC% Report copied to: %REPORT_DIR%
    ) else (
        echo %YELLOW%⚠%NC% No dependency report generated
    )
) else (
    echo %RED%✗%NC% Dependency check failed

    :: Try to copy partial report anyway
    for /f "delims=" %%i in ('dir /s /b "app\build\reports\dependency-check-report.html" 2^>nul') do (
        copy "%%i" "%REPORT_DIR%\" >nul 2>&1
        goto :found_partial
    )
    :found_partial
)

:: Display summary
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Dependency Check Summary                   ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

if %DEP_EXIT_CODE% EQU 0 (
    echo %GREEN%✓ Dependency check passed%NC%
) else (
    echo %RED%✗ Vulnerabilities detected - review report%NC%
)

:: Generate summary
echo. > "%REPORT_DIR%\dep-check-summary.txt"
echo ======================================== >> "%REPORT_DIR%\dep-check-summary.txt"
echo OWASP Dependency Check Summary >> "%REPORT_DIR%\dep-check-summary.txt"
echo ======================================== >> "%REPORT_DIR%\dep-check-summary.txt"
if %DEP_EXIT_CODE% EQU 0 (
    echo Status: PASSED >> "%REPORT_DIR%\dep-check-summary.txt"
) else (
    echo Status: FAILED >> "%REPORT_DIR%\dep-check-summary.txt"
)
echo Timestamp: %date% %time% >> "%REPORT_DIR%\dep-check-summary.txt"
echo. >> "%REPORT_DIR%\dep-check-summary.txt"
echo Report Location: >> "%REPORT_DIR%\dep-check-summary.txt"
echo - HTML: %REPORT_DIR%\dependency-check-report.html >> "%REPORT_DIR%\dep-check-summary.txt"
echo - Log: %REPORT_DIR%\dep-check-output.log >> "%REPORT_DIR%\dep-check-summary.txt"

type "%REPORT_DIR%\dep-check-summary.txt"

:: Display report location
if exist "%REPORT_DIR%\dependency-check-report.html" (
    echo.
    echo %BLUE%ℹ%NC% HTML Report: %REPORT_DIR%\dependency-check-report.html
)

echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Complete                                   ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%

exit /b %DEP_EXIT_CODE%
