@echo off
echo Downloading ktlint 1.0.1...
echo.
echo If download fails, please download manually from:
echo https://github.com/pinterest/ktlint/releases/download/1.0.1/ktlint.jar
echo.
echo Place the file in: %~dp0ktlint.jar
echo.

cd /d "%~dp0"

:: Try using PowerShell with TLS 1.2
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Write-Host 'Attempting download...'; try { Invoke-WebRequest -Uri 'https://github.com/pinterest/ktlint/releases/download/1.0.1/ktlint.jar' -OutFile 'ktlint.jar' -TimeoutSec 30; Write-Host 'Download complete!' } catch { Write-Host 'Download failed:'; Write-Host $_.Exception.Message; exit 1 }"

if exist ktlint.jar (
    echo.
    echo Success! ktlint.jar downloaded.
    dir ktlint.jar
) else (
    echo.
    echo Download failed. Please download manually from:
    echo https://github.com/pinterest/ktlint/releases/download/1.0.1/ktlint.jar
    echo.
    echo Then place it in: %~dp0ktlint.jar
)
