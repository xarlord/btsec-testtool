@echo off
###########################################
# Unit Tests with Coverage
# Replicates unit-tests job from .github/workflows/ci.yml
###########################################

setlocal enabledelayedexpansion

:: Project root
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
set "REPORT_DIR=%PROJECT_ROOT%\build\local-ci-reports\test"

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
echo %BLUE%^|🧪 Unit Tests with Coverage                ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

:: Create report directory
echo %BLUE%ℹ%NC% Creating report directory...
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

:: Change to project root
cd /d "%PROJECT_ROOT%"

:: Run unit tests for all flavors
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Running Unit Tests (Dev + Prod Flavors)   ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %BLUE%ℹ%NC% Running: gradlew.bat test testDevDebugUnitTest testProdDebugUnitTest --stacktrace

call gradlew.bat test testDevDebugUnitTest testProdDebugUnitTest --stacktrace > "%REPORT_DIR%\test-output.log" 2>&1
set "TEST_EXIT_CODE=%ERRORLEVEL%"

if %TEST_EXIT_CODE% EQU 0 (
    echo %GREEN%✓%NC% Unit tests passed
) else (
    echo %RED%✗%NC% Unit tests failed
    set "TEST_EXIT_CODE=1"
)

:: Always generate coverage report
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Generating Coverage Report                ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %BLUE%ℹ%NC% Running: gradlew.bat jacocoTestReport

call gradlew.bat jacocoTestReport >> "%REPORT_DIR%\test-output.log" 2>&1
if errorlevel 1 (
    echo %YELLOW%⚠%NC% Coverage report generation failed ^(continuing anyway^)
) else (
    echo %GREEN%✓%NC% Coverage report generated
)

:: Collect test results
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Collecting Test Results                   ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

:: Copy test reports
echo %BLUE%ℹ%NC% Copying test reports...
if not exist "%REPORT_DIR%\test-results" mkdir "%REPORT_DIR%\test-results"
if exist "app\build\test-results" xcopy /E /I /Y "app\build\test-results\*" "%REPORT_DIR%\test-results\" >nul 2>&1

if not exist "%REPORT_DIR%\reports" mkdir "%REPORT_DIR%\reports"
if exist "app\build\reports\tests" xcopy /E /I /Y "app\build\reports\tests\*" "%REPORT_DIR%\reports\" >nul 2>&1

:: Copy coverage reports
echo %BLUE%ℹ%NC% Copying coverage reports...
if not exist "%REPORT_DIR%\coverage" mkdir "%REPORT_DIR%\coverage"
if exist "app\build\reports\jacoco" xcopy /E /I /Y "app\build\reports\jacoco\*" "%REPORT_DIR%\coverage\" >nul 2>&1

:: Find coverage HTML report
set "COVERAGE_HTML="
for /f "delims=" %%i in ('dir /s /b "%REPORT_DIR%\coverage\index.html" 2^>nul') do (
    set "COVERAGE_HTML=%%i"
    goto :found_coverage
)
:found_coverage

:: Generate test summary
echo. > "%REPORT_DIR%\test-summary.txt"
echo ======================================== >> "%REPORT_DIR%\test-summary.txt"
echo Test Summary >> "%REPORT_DIR%\test-summary.txt"
echo ======================================== >> "%REPORT_DIR%\test-summary.txt"
if %TEST_EXIT_CODE% EQU 0 (
    echo Status: PASSED >> "%REPORT_DIR%\test-summary.txt"
) else (
    echo Status: FAILED >> "%REPORT_DIR%\test-summary.txt"
)
echo Timestamp: %date% %time% >> "%REPORT_DIR%\test-summary.txt"
echo. >> "%REPORT_DIR%\test-summary.txt"
echo Test Results: >> "%REPORT_DIR%\test-summary.txt"
echo See test results XML in: %REPORT_DIR%\test-results\ >> "%REPORT_DIR%\test-summary.txt"
echo. >> "%REPORT_DIR%\test-summary.txt"
echo Coverage Report: >> "%REPORT_DIR%\test-summary.txt"
if defined COVERAGE_HTML (
    echo - HTML: !COVERAGE_HTML! >> "%REPORT_DIR%\test-summary.txt"
)
echo. >> "%REPORT_DIR%\test-summary.txt"
echo Reports Location: >> "%REPORT_DIR%\test-summary.txt"
echo - Test results: %REPORT_DIR%\test-results\ >> "%REPORT_DIR%\test-summary.txt"
echo - Test reports: %REPORT_DIR%\reports\ >> "%REPORT_DIR%\test-summary.txt"
echo - Coverage: %REPORT_DIR%\coverage\ >> "%REPORT_DIR%\test-summary.txt"
echo - Full log: %REPORT_DIR%\test-output.log >> "%REPORT_DIR%\test-summary.txt"

:: Display summary
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Test Results Summary                      ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

if %TEST_EXIT_CODE% EQU 0 (
    echo %GREEN%✓%NC% Tests passed
) else (
    echo %RED%✗%NC% Tests failed
)

echo.
echo %BLUE%ℹ%NC% Reports saved to: %REPORT_DIR%
type "%REPORT_DIR%\test-summary.txt"

echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Complete                                   ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%

exit /b %TEST_EXIT_CODE%
