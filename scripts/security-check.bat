@echo off
###########################################
# Security Checklist
# Replicates security-checklist job from .github/workflows/ci.yml
###########################################

setlocal enabledelayedexpansion

:: Project root
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
set "REPORT_DIR=%PROJECT_ROOT%\build\local-ci-reports\security"

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
echo %BLUE%^|🔒 Security Checklist                      ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

:: Create report directory
echo %BLUE%ℹ%NC% Creating report directory...
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

:: Change to project root
cd /d "%PROJECT_ROOT%"

:: Track overall status
set "SECURITY_EXIT_CODE=0"

:: 1. Check for hardcoded secrets
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|1. Hardcoded Secrets Check                 ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %BLUE%ℹ%NC% Scanning for potential hardcoded secrets...

set "SECRETS_FOUND=0"

:: Simple pattern matching for secrets
findstr /S /I /C:"sk_" /C:"pk_" /C:"apiKey" /C:"secret =" /C:"password =" /C:"token =" app\src\main\*.kt >nul 2>&1
if errorlevel 1 (
    echo %GREEN%✓%NC% No hardcoded secrets detected
) else (
    echo %RED%✗%NC% Potential hardcoded secrets found
    set "SECRETS_FOUND=1"
    set "SECURITY_EXIT_CODE=1"
)

:: 2. Verify Android permissions
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|2. Android Permissions Check               ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %BLUE%ℹ%NC% Checking Android permissions...

set "MANIFEST_FILE=app\src\main\AndroidManifest.xml"
set "PERMISSIONS_OK=1"

if not exist "%MANIFEST_FILE%" (
    echo %RED%✗%NC% AndroidManifest.xml not found
    set "PERMISSIONS_OK=0"
    set "SECURITY_EXIT_CODE=1"
) else (
    findstr /C:"BLUETOOTH_CONNECT" "%MANIFEST_FILE%" >nul 2>&1
    if errorlevel 1 (
        echo %RED%✗%NC% Missing BLUETOOTH_CONNECT permission
        set "PERMISSIONS_OK=0"
        set "SECURITY_EXIT_CODE=1"
    )

    findstr /C:"BLUETOOTH_SCAN" "%MANIFEST_FILE%" >nul 2>&1
    if errorlevel 1 (
        echo %RED%✗%NC% Missing BLUETOOTH_SCAN permission
        set "PERMISSIONS_OK=0"
        set "SECURITY_EXIT_CODE=1"
    )
)

if %PERMISSIONS_OK% EQU 1 (
    echo %GREEN%✓%NC% All required permissions present
)

:: 3. Verify authorization enforcement
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|3. Authorization Enforcement Check         ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %BLUE%ℹ%NC% Checking for authorization enforcement...

findstr /S /C:"requestActionAuthorization" app\src\main\*.kt >nul 2>&1
if errorlevel 1 (
    echo %YELLOW%⚠%NC% Authorization checks may be missing
) else (
    echo %GREEN%✓%NC% Authorization enforcement found
)

findstr /S /C:"TestScope" app\src\main\*.kt >nul 2>&1
if errorlevel 1 (
    echo %RED%✗%NC% TestScope validation not found
    set "SECURITY_EXIT_CODE=1"
) else (
    echo %GREEN%✓%NC% TestScope validation found
)

:: 4. Verify consent tracking
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|4. Consent Tracking Check                  ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %BLUE%ℹ%NC% Checking consent tracking...

findstr /S /C:"ConsentRepository" app\src\main\*.kt >nul 2>&1
if errorlevel 1 (
    echo %RED%✗%NC% Consent tracking not implemented
    set "SECURITY_EXIT_CODE=1"
) else (
    echo %GREEN%✓%NC% ConsentRepository found
)

findstr /S /C:"logAuditEvent" app\src\main\*.kt >nul 2>&1
if errorlevel 1 (
    echo %YELLOW%⚠%NC% Audit logging may be incomplete
) else (
    echo %GREEN%✓%NC% Audit logging found
)

:: 5. Check for legal disclaimers
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|5. Legal Disclaimers Check                  ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.
echo %BLUE%ℹ%NC% Checking for legal disclaimers...

for /f %%i in ('findstr /S /C:"AUTHORIZED security testing" app\src\main\*.kt 2^>nul ^| find /c /v ""') do set "DISCLAIMER_COUNT=%%i"

if %DISCLAIMER_COUNT% GEQ 5 (
    echo %GREEN%✓%NC% Legal disclaimers found (%DISCLAIMER_COUNT% files)
) else (
    echo %YELLOW%⚠%NC% Legal disclaimers may be missing (%DISCLAIMER_COUNT% files)
)

:: Generate summary
echo. > "%REPORT_DIR%\security-summary.txt"
echo ======================================== >> "%REPORT_DIR%\security-summary.txt"
echo Security Checklist Summary >> "%REPORT_DIR%\security-summary.txt"
echo ======================================== >> "%REPORT_DIR%\security-summary.txt"
if %SECURITY_EXIT_CODE% EQU 0 (
    echo Status: PASSED >> "%REPORT_DIR%\security-summary.txt"
) else (
    echo Status: FAILED >> "%REPORT_DIR%\security-summary.txt"
)
echo Timestamp: %date% %time% >> "%REPORT_DIR%\security-summary.txt"
echo. >> "%REPORT_DIR%\security-summary.txt"
echo Checks Results: >> "%REPORT_DIR%\security-summary.txt"
echo 1. Hardcoded Secrets: %SECRETS_FOUND% found >> "%REPORT_DIR%\security-summary.txt"
echo 2. Android Permissions: %PERMISSIONS_OK% >> "%REPORT_DIR%\security-summary.txt"
echo 7. Legal Disclaimers: %DISCLAIMER_COUNT% files >> "%REPORT_DIR%\security-summary.txt"

:: Display summary
echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Security Summary                           ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo.

if %SECURITY_EXIT_CODE% EQU 0 (
    echo %GREEN%✓ All critical security checks passed%NC%
) else (
    echo %RED%✗ Some security checks failed - review above%NC%
)

type "%REPORT_DIR%\security-summary.txt"

echo.
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%
echo %BLUE%^|Complete                                   ^|%NC%
echo %BLUE%━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%NC%

exit /b %SECURITY_EXIT_CODE%
