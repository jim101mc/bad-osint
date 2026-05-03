@echo off
powershell -ExecutionPolicy Bypass -File "%~dp0start.badosint.ps1" %*
exit /b %ERRORLEVEL%
