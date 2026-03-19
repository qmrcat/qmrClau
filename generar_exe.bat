@echo off
REM ============================================
REM  qmrClau - Script per generar .exe portable
REM  Windows 10/11
REM ============================================
REM
REM  Requisits:
REM    1. Python 3.8+ instal·lat (https://python.org)
REM    2. pip instal·lat (ve amb Python)
REM
REM  Ús: Fes doble clic a aquest fitxer .bat
REM       o executa'l des del CMD/PowerShell
REM ============================================

echo.
echo  ==============================
echo   qmrClau - Generador d'EXE
echo  ==============================
echo.

REM Instal·lar PyInstaller si cal
echo [1/3] Instal·lant PyInstaller...
pip install pyinstaller --quiet
if %errorlevel% neq 0 (
    echo ERROR: No s'ha pogut instal·lar PyInstaller.
    echo Assegura't que Python i pip estan instal·lats.
    pause
    exit /b 1
)

echo.
echo [2/3] Generant l'executable portable...
echo        Això pot trigar 1-2 minuts...
echo.

REM Generar executable
pyinstaller ^
    --onefile ^
    --noconsole ^
    --name qmrClau ^
    --clean ^
    qmrclau.py

if %errorlevel% neq 0 (
    echo.
    echo ERROR: La compilacio ha fallat.
    pause
    exit /b 1
)

echo.
echo [3/3] Fet!
echo.
echo  L'executable es troba a:
echo    dist\qmrClau.exe
echo.
echo  Aquest fitxer es PORTABLE:
echo  - Copia qmrClau.exe a una USB o carpeta qualsevol
echo  - No necessita instal·lacio
echo  - Les bases de dades .vkdb es poden guardar al costat
echo.
echo  Mida aproximada: 8-12 MB
echo.

REM Obrir la carpeta dist
explorer dist

pause