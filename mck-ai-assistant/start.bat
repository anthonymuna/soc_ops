@echo off
echo ========================================================
echo Methodist Church Kenya AI Assistant - Local Server
echo ========================================================
if not exist "venv\" (
    echo Error: Virtual environment (venv) not found!
    echo Please run the installation command first.
    pause
    exit /b
)
echo Activating virtual environment...
call venv\Scripts\activate
echo Database initialized automatically on start.
echo Starting FastAPI application...
echo The Web Dashboard will be available at http://localhost:8000
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
pause
