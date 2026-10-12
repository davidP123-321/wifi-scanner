$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$folder = Join-Path $root 'wifi-dashboard-package'
$zipPath = Join-Path $root 'wifi-dashboard-package.zip'

if (Test-Path $folder) { Remove-Item -Recurse -Force $folder }
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }

New-Item -ItemType Directory -Path $folder | Out-Null
Copy-Item (Join-Path $root 'wifi_dashboard_server.py') $folder
Copy-Item (Join-Path $root 'index.html') $folder
Copy-Item (Join-Path $root 'launch_wifi_dashboard.bat') $folder

@"
@echo off
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
    py wifi_dashboard_server.py
) else (
    python wifi_dashboard_server.py
)
pause
"@ | Set-Content -Path (Join-Path $folder 'launch_wifi_dashboard.bat') -Encoding ASCII

Compress-Archive -Path $folder -DestinationPath $zipPath -Force

Write-Host "ZIP generated: $zipPath"
Write-Host "Open it on your PC, then launch launch_wifi_dashboard.bat"
