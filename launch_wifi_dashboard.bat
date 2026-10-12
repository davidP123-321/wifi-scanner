@echo off
cd /d "%USERPROFILE%\Downloads\wifi-dashboard"

where py >nul 2>nul
if not errorlevel 1 (
    py wifi_dashboard_server.py
) else (
    python wifi_dashboard_server.py
)

pause
