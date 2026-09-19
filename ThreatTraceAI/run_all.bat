@echo off
title ThreatTrace AI - Launcher
echo ===================================================
echo   THREAT TRACE AI - FORENSIC PLATFORM
echo ===================================================
echo Starting backend (FastAPI :8000) and frontend (Vite :5173)...

start "ThreatTrace Backend" cmd /k "cd /d "%~dp0backend" && python -m uvicorn app.main:app --reload --port 8000 --host 127.0.0.1"
timeout /t 2 /nobreak >nul
start "ThreatTrace Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo Servers launched!
echo Frontend: http://localhost:5173
echo Backend:  http://127.0.0.1:8000/docs
echo ===================================================
