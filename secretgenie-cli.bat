@echo off
setlocal
set "HERE=%~dp0"

if exist "%HERE%secretgenie.exe" (
    "%HERE%secretgenie.exe" %*
    exit /b %ERRORLEVEL%
)
if exist "%HERE%secretgenie-hsbc.exe" (
    "%HERE%secretgenie-hsbc.exe" %*
    exit /b %ERRORLEVEL%
)

echo ERROR: secretgenie.exe not found next to this wrapper. 1>&2
exit /b 1
