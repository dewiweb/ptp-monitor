@echo off
REM Build PTPMonitor.exe (single portable executable) with PyInstaller.
cd /d "%~dp0"
pip install -r requirements-build.txt
python -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name PTPMonitor main.py
if exist devices.json copy /y devices.json dist\ >nul
echo.
echo Resultat : dist\PTPMonitor.exe
echo (optionnel : devices.json et oui.csv se placent a cote de l'exe)
