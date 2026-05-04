@echo off
setlocal
echo Building SecretGenie CLI...

if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

python -m pip install -r requirements.txt

set HSBC_BUILD=false
set SPEC=packaging\genie.spec
set NAME=secretgenie.exe

if "%1"=="hsbc" (
    echo Building HSBC variant...
    set HSBC_BUILD=true
    set SPEC=packaging\genie-hsbc.spec
    set NAME=secretgenie-hsbc.exe
)

pyinstaller --clean %SPEC%
if errorlevel 1 goto :fail

copy secretgenie-cli.bat dist\secretgenie-cli.bat >nul 2>&1
copy secretgenie-cli.ps1 dist\secretgenie-cli.ps1 >nul 2>&1

echo.
echo Build complete.
echo   Binary:   dist\%NAME%
echo   Wrappers: dist\secretgenie-cli.bat, dist\secretgenie-cli.ps1
if "%HSBC_BUILD%"=="true" echo   Variant:  HSBC
endlocal
exit /b 0

:fail
echo Build failed.
endlocal
exit /b 1
