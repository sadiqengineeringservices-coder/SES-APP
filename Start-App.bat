@echo off
title Sadiq Engineering Services - Offline App
echo.
echo ============================================
echo   Sadiq Engineering Services - Offline App
echo ============================================
echo.
echo  Launching the desktop app...
echo  (Keep this window open while using the app,
echo   or close it after the app window appears.)
echo.

cd /d "%~dp0"

REM Launch the packaged Electron app if it exists
if exist "dist-electron\win-unpacked\SES Offline Workshop.exe" (
  start "" "dist-electron\win-unpacked\SES Offline Workshop.exe"
  goto launched
)

REM Or the installed app (typical install location)
if exist "%LOCALAPPDATA%\Programs\SES Offline Workshop\SES Offline Workshop.exe" (
  start "" "%LOCALAPPDATA%\Programs\SES Offline Workshop\SES Offline Workshop.exe"
  goto launched
)

REM Otherwise launch Electron directly with the built files
if exist "node_modules\.bin\electron.cmd" (
  start "" "node_modules\.bin\electron.cmd" .
  goto launched
)

REM Final fallback: start the Vite dev server and open in browser
echo  Standing up local server... please wait.
start /min cmd /c "npm run dev"
timeout /t 6 /nobreak >nul
start http://localhost:5173/

:launched
echo.
echo  The app is now open.
echo  When you are done, just close the app window.
echo.
pause
