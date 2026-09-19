@echo off
title ThreatTrace AI - Backend Server
cd /d "%~dp0backend"
echo [ThreatTrace AI] Starting FastAPI Forensic Backend on http://127.0.0.1:8000 ...
python -m uvicorn app.main:app --reload --port 8000 --host 127.0.0.1
pause
