@echo off
REM Start server in background
start /B go run ./cmd/server
timeout /t 3 /nobreak

REM Run agent briefly to send one heartbeat
timeout /t 1 /nobreak & go run ./cmd/agent
