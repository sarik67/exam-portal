@echo off
REM ================================================================
REM  ExamPortal - Production Launch Script (Windows)
REM  Handles 1000+ concurrent students via Waitress WSGI server
REM ================================================================

echo.
echo  ============================================
echo   ExamPortal Production Server
echo   1000 concurrent students supported
echo  ============================================
echo.

cd /d "%~dp0"

REM Optional: set env vars here or use a .env file
REM set DB_PASSWORD=your_password
REM set SECRET_KEY=your_random_64_char_secret

REM Start with production mode
python app.py --prod

pause
