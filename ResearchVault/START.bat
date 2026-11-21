@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Jalankan INSTALL.bat terlebih dahulu.
  pause
  exit /b 1
)
if not exist "native\researchvault_hello.dll" (
  echo Adapter Hello belum tersedia. Jalankan BUILD_HELLO.bat.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" main.py
if errorlevel 1 pause
