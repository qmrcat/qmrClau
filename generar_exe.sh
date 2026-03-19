#!/bin/bash
# ============================================
#  qmrClau - Script per generar executable portable
#  Linux (Debian/Ubuntu/Fedora/Arch...)
# ============================================
#
#  Requisits:
#    1. Python 3.8+
#    2. pip
#    3. tkinter (python3-tk)
#
#  Ús: chmod +x generar_exe.sh && ./generar_exe.sh
# ============================================

set -e

echo ""
echo "  =============================="
echo "   qmrClau - Generador Linux"
echo "  =============================="
echo ""

# Comprovar Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 no trobat."
    echo "Instal·la'l amb:"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "  Fedora:        sudo dnf install python3 python3-pip"
    echo "  Arch:          sudo pacman -S python python-pip"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1)
echo "  Python trobat: $PYTHON_VERSION"

# Comprovar tkinter
echo ""
echo "[1/4] Comprovant tkinter..."
if ! python3 -c "import tkinter" &> /dev/null; then
    echo ""
    echo "ERROR: tkinter no està instal·lat."
    echo "Instal·la'l amb:"
    echo "  Ubuntu/Debian: sudo apt install python3-tk"
    echo "  Fedora:        sudo dnf install python3-tkinter"
    echo "  Arch:          sudo pacman -S tk"
    echo ""
    echo "Després torna a executar aquest script."
    exit 1
fi
echo "  tkinter OK"

# Instal·lar PyInstaller
echo ""
echo "[2/4] Instal·lant PyInstaller..."
pip3 install pyinstaller --quiet --break-system-packages 2>/dev/null || \
pip3 install pyinstaller --quiet 2>/dev/null || \
python3 -m pip install pyinstaller --quiet --break-system-packages 2>/dev/null || \
python3 -m pip install pyinstaller --quiet

echo "  PyInstaller OK"

# Obtenir el directori de l'script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Comprovar que qmrclau.py existeix
if [ ! -f "qmrclau.py" ]; then
    echo ""
    echo "ERROR: No es troba qmrclau.py al directori actual."
    echo "Assegura't que aquest script està a la mateixa carpeta que qmrclau.py"
    exit 1
fi

# Generar executable
echo ""
echo "[3/4] Generant l'executable portable..."
echo "       Això pot trigar 1-2 minuts..."
echo ""

pyinstaller \
    --onefile \
    --noconsole \
    --name qmrClau \
    --clean \
    qmrclau.py

# Fer-lo executable
chmod +x dist/qmrClau

# Resum
echo ""
echo "[4/4] Fet!"
echo ""
echo "  L'executable es troba a:"
echo "    $SCRIPT_DIR/dist/qmrClau"
echo ""
echo "  Aquest fitxer és PORTABLE:"
echo "  - Copia qmrClau a una USB o carpeta qualsevol"
echo "  - No necessita instal·lació"
echo "  - Les bases de dades .vkdb es poden guardar al costat"
echo ""

# Mostrar mida
SIZE=$(du -h dist/qmrClau | cut -f1)
echo "  Mida: $SIZE"
echo ""

# Preguntar si vol executar-lo
read -p "  Vols executar qmrClau ara? (s/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Ss]$ ]]; then
    echo "  Iniciant qmrClau..."
    ./dist/qmrClau &
fi

echo ""
echo "  Gràcies per usar qmrClau!"
echo ""