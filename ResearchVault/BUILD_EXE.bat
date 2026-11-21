@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
 echo Jalankan INSTALL.bat dahulu.
 pause
 exit /b 1
)
call BUILD_HELLO.bat
if errorlevel 1 goto fail
".venv\Scripts\python.exe" -m pip install -r requirements-dev.txt
if errorlevel 1 goto fail
".venv\Scripts\python.exe" -m pytest tests -q
if errorlevel 1 goto fail
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --windowed --onedir --name ResearchVault --add-binary "native\researchvault_hello.dll;native" --hidden-import win32timezone --hidden-import win32com.client main.py
if errorlevel 1 goto fail
echo EXE tersedia di dist\ResearchVault\ResearchVault.exe
echo Salin seluruh folder dist\ResearchVault, bukan hanya file EXE.
pause
exit /b 0
:fail
echo Build belum berhasil. Periksa pesan di atas.
pause
exit /b 1
