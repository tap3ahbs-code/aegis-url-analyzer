@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 update_threats.py
) else (
    python update_threats.py
)
pause
