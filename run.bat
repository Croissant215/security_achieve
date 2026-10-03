@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -c "import flask; import importlib.metadata as m; assert m.version('flask') == '3.1.3'" >nul 2>&1
if errorlevel 1 (
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 goto failed
)
echo Open http://127.0.0.1:5000 in your browser.
echo Press Ctrl+C to stop the local server.
".venv\Scripts\python.exe" app.py
if errorlevel 1 goto failed
exit /b 0
:failed
echo Setup or startup failed. Read README.md for troubleshooting.
pause
exit /b 1
