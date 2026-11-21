@echo off
setlocal
cd /d "%~dp0"
echo ResearchVault - instalasi Python dependencies
py -3.12 --version >nul 2>&1
if errorlevel 1 (
  echo Python 3.12 x64 belum ditemukan. Pasang dari python.org, lalu jalankan lagi.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" py -3.12 -m venv .venv
if errorlevel 1 goto fail
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto fail
call BUILD_HELLO.bat
if errorlevel 1 goto fail
echo Selesai. Jalankan START.bat untuk membuka aplikasi.
pause
exit /b 0
:fail
echo Instalasi belum selesai. Baca pesan di atas dan README.md.
pause
exit /b 1
