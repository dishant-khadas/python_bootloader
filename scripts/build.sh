#!/bin/bash
# Build script for CZAR Bootloader Application
# Run this on Raspberry Pi 4 to create the executable

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo "========================================="
echo "  CZAR Bootloader Build Script"
echo "========================================="

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "[1/4] Creating virtual environment..."
    python3 -m venv venv
else
    echo "[1/4] Virtual environment already exists"
fi

# Activate venv
echo "[2/4] Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "[3/4] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

# Build executable
echo "[4/4] Building executable with PyInstaller..."
pyinstaller bootloader.spec --clean

echo ""
echo "========================================="
echo "  Build Complete!"
echo "========================================="
echo ""
echo "Executable location: dist/czar_bootloader/"
echo ""
echo "To run the application:"
echo "  cd dist/czar_bootloader"
echo "  ./czar_bootloader"
echo ""
echo "To distribute:"
echo "  Copy the entire 'dist/czar_bootloader' folder"
echo "  to your target Raspberry Pi."
echo ""
