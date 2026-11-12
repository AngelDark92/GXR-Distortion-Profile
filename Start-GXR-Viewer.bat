@echo off
rem Build the GXR optical LUT viewer and open it in your browser.
rem
rem   Start-GXR-Viewer.bat            build, serve on 127.0.0.1, open browser
rem   Start-GXR-Viewer.bat --direct   build and open the HTML file directly
rem
rem The server keeps running until this window is closed or Ctrl+C is pressed.
setlocal EnableExtensions
cd /d "%~dp0"

set "OUT=viewer\optics-viewer.html"
set "PY="

where py >nul 2>nul
if %errorlevel%==0 set "PY=py"
if not defined PY (
  where python >nul 2>nul
  if %errorlevel%==0 set "PY=python"
)
if not defined PY (
  echo.
  echo Python 3 was not found on PATH. Install Python 3, then run this file again.
  echo Or open %OUT% manually after building it with build_viewer.py.
  echo.
  pause
  exit /b 1
)

echo Building %OUT% ...
%PY% -B build_viewer.py data\analysis.json -o "%OUT%"
if errorlevel 1 (
  echo.
  echo Build failed. The viewer was not opened.
  pause
  exit /b 1
)

echo Preparing download assets ...
%PY% -B tools\build_pages.py --assets-only viewer
if errorlevel 1 (
  echo.
  echo Download asset build failed. The viewer was not opened.
  pause
  exit /b 1
)

if /I "%~1"=="--direct" (
  echo Opening %OUT% directly.
  start "" "%OUT%"
  exit /b 0
)

echo Starting local viewer server ...
%PY% -B tools\serve_viewer.py --root viewer --file optics-viewer.html
if errorlevel 1 (
  echo.
  echo Could not start the local server. Falling back to opening the file directly.
  start "" "%OUT%"
  pause
)
endlocal
