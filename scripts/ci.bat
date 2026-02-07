@echo off
:: ###########################################
:: Master CI/CD Orchestration Script
:: Runs all CI checks in sequence
:: ###########################################

setlocal enabledelayedexpansion

:: Project root
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."

:: ANSI color codes
for /F %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"
set "RED=%ESC%[31m"
set "GREEN=%ESC%[32m"
set "YELLOW=%ESC%[33m"
set "BLUE=%ESC%[34m"
set "CYAN=%ESC%[36m"
set "BOLD=%ESC%[1m"
set "NC=%ESC%[0m"

:: Overall timer
set "START_TIME=%time%"

:: Track results
set "LINT_RESULT=FAILED"
set "TEST_RESULT=FAILED"
set "SECURITY_RESULT=FAILED"
set "DEPCHECK_RESULT=FAILED"
set "BUILD_RESULT=FAILED"

echo.
echo %CYAN%╔════════════════════════════════════════╗%NC%
echo %CYAN%║%NC% %BOLD%🚀 Local CI/CD Pipeline                %NC%%CYAN%║%NC%
echo %CYAN%╚════════════════════════════════════════╝%NC%
echo.
echo %BLUE%ℹ%NC% Project: %PROJECT_ROOT%
echo %BLUE%ℹ%NC% Started: %date% %time%
echo.

:: Change to project root
cd /d "%PROJECT_ROOT%"

:: ============================================
:: STEP 1: Linting
:: ============================================
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%  [STEP 1/5] Linting (ktlint + Android Lint)%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

call "%SCRIPT_DIR%lint.bat"
if errorlevel 1 (
    set "LINT_RESULT=FAILED"
    echo %RED%✗%NC% Linting failed
) else (
    set "LINT_RESULT=PASSED"
    echo %GREEN%✓%NC% Linting passed
)

:: ============================================
:: STEP 2: Unit Tests
:: ============================================
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%  [STEP 2/5] Unit Tests with Coverage     %NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

call "%SCRIPT_DIR%test.bat"
if errorlevel 1 (
    set "TEST_RESULT=FAILED"
    echo %RED%✗%NC% Tests failed
) else (
    set "TEST_RESULT=PASSED"
    echo %GREEN%✓%NC% Tests passed
)

:: ============================================
:: STEP 3: Security Checks
:: ============================================
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%  [STEP 3/5] Security Validation          %NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

call "%SCRIPT_DIR%security-check.bat"
if errorlevel 1 (
    set "SECURITY_RESULT=FAILED"
    echo %RED%✗%NC% Security checks failed
) else (
    set "SECURITY_RESULT=PASSED"
    echo %GREEN%✓%NC% Security checks passed
)

:: ============================================
:: STEP 4: Dependency Check
:: ============================================
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%  [STEP 4/5] OWASP Dependency Scan        %NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

call "%SCRIPT_DIR%dep-check.bat"
if errorlevel 1 (
    set "DEPCHECK_RESULT=FAILED"
    echo %RED%✗%NC% Dependency check failed
) else (
    set "DEPCHECK_RESULT=PASSED"
    echo %GREEN%✓%NC% Dependency check passed
)

:: ============================================
:: STEP 5: Build
:: ============================================
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%  [STEP 5/5] Build APKs (Debug + Release) %NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

call "%SCRIPT_DIR%build.bat"
if errorlevel 1 (
    set "BUILD_RESULT=FAILED"
    echo %RED%✗%NC% Build failed
) else (
    set "BUILD_RESULT=PASSED"
    echo %GREEN%✓%NC% Build passed
)

:: ============================================
:: FINAL SUMMARY
:: ============================================
echo.
echo.
echo %CYAN%╔════════════════════════════════════════╗%NC%
echo %CYAN%║%NC% %BOLD%📊 CI/CD Pipeline Summary              %NC%%CYAN%║%NC%
echo %CYAN%╚════════════════════════════════════════╝%NC%
echo.
echo ┌──────────────┬────────┐
echo │ Check        │ Status │
echo ├──────────────┼────────┤

:: Display results
if "%LINT_RESULT%"=="PASSED" (
    echo │ Linting      │ %GREEN%PASSED%NC% │
) else (
    echo │ Linting      │ %RED%FAILED%NC% │
)

if "%TEST_RESULT%"=="PASSED" (
    echo │ Unit Tests   │ %GREEN%PASSED%NC% │
) else (
    echo │ Unit Tests   │ %RED%FAILED%NC% │
)

if "%SECURITY_RESULT%"=="PASSED" (
    echo │ Security     │ %GREEN%PASSED%NC% │
) else (
    echo │ Security     │ %RED%FAILED%NC% │
)

if "%DEPCHECK_RESULT%"=="PASSED" (
    echo │ Dep. Check   │ %GREEN%PASSED%NC% │
) else (
    echo │ Dep. Check   │ %RED%FAILED%NC% │
)

if "%BUILD_RESULT%"=="PASSED" (
    echo │ Build        │ %GREEN%PASSED%NC% │
) else (
    echo │ Build        │ %RED%FAILED%NC% │
)

echo └──────────────┴────────┘
echo.

:: Count failures
set "FAILURES=0"
if "%LINT_RESULT%"=="FAILED" set /a FAILURES+=1
if "%TEST_RESULT%"=="FAILED" set /a FAILURES+=1
if "%SECURITY_RESULT%"=="FAILED" set /a FAILURES+=1
if "%DEPCHECK_RESULT%"=="FAILED" set /a FAILURES+=1
if "%BUILD_RESULT%"=="FAILED" set /a FAILURES+=1

:: Overall result
echo %BLUE%ℹ%NC% Completed: %date% %time%
echo.

if %FAILURES% EQU 0 (
    echo.
    echo %CYAN%╔════════════════════════════════════════╗%NC%
    echo %CYAN%║%NC% %BOLD%✅ ALL CHECKS PASSED                  %NC%%CYAN%║%NC%
    echo %CYAN%╚════════════════════════════════════════╝%NC%
    echo.
    echo %GREEN%✓%NC% CI/CD pipeline completed successfully
    echo.
    echo %BLUE%ℹ%NC% Reports location: %PROJECT_ROOT%\build\local-ci-reports\
    exit /b 0
) else (
    echo.
    echo %CYAN%╔════════════════════════════════════════╗%NC%
    echo %CYAN%║%NC% %BOLD%❌ CI/CD PIPELINE FAILED               %NC%%CYAN%║%NC%
    echo %CYAN%╚════════════════════════════════════════╝%NC%
    echo.
    echo %RED%✗%NC% %FAILURES% check(s) failed:
    if "%LINT_RESULT%"=="FAILED" echo   - Linting
    if "%TEST_RESULT%"=="FAILED" echo   - Unit Tests
    if "%SECURITY_RESULT%"=="FAILED" echo   - Security
    if "%DEPCHECK_RESULT%"=="FAILED" echo   - Dependency Check
    if "%BUILD_RESULT%"=="FAILED" echo   - Build
    echo.
    echo %BLUE%ℹ%NC% Reports location: %PROJECT_ROOT%\build\local-ci-reports\
    exit /b 1
)
