@echo off
powershell -ExecutionPolicy Bypass -File "%~dp0install.badosint.ps1" %*
exit /b %ERRORLEVEL%
