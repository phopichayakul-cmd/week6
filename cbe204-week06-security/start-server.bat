@echo off
cd /d "%~dp0"
call npm run seed
call npm start
pause
