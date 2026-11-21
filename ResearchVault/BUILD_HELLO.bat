@echo off
setlocal
cd /d "%~dp0"
where cl >nul 2>&1
if not errorlevel 1 goto compile
set "RV_VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%RV_VSWHERE%" goto missing
for /f "usebackq tokens=*" %%i in (`"%RV_VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "RV_VS=%%i"
if not defined RV_VS goto missing
call "%RV_VS%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
:compile
cl /nologo /std:c++17 /EHsc /O2 /MD /LD native\hello.cpp /Fo:native\hello.obj /link windowsapp.lib /OUT:native\researchvault_hello.dll
if errorlevel 1 exit /b 1
echo Adapter Windows Hello selesai dibangun.
exit /b 0
:missing
echo Visual Studio Build Tools belum tersedia.
echo Pasang workload Desktop development with C++ dan Windows 11 SDK 10.0.22621 atau lebih baru.
echo Lalu jalankan INSTALL.bat kembali. Petunjuk lengkap ada di README.md.
exit /b 1
