#!/bin/bash
# Install script for CZAR Bootloader desktop icon (Executable version)
# Run this on Raspberry Pi after building the executable

set -e

# Configuration
APP_DIR="/home/czar/app/python_bootloader"
DIST_DIR="$APP_DIR/dist/czar_bootloader"
DESKTOP_FILE="czar_bootloader.desktop"

echo "========================================="
echo "  CZAR Bootloader - Desktop Icon Setup"
echo "========================================="

# Check if the executable exists
if [ ! -f "$DIST_DIR/czar_bootloader" ]; then
    echo ""
    echo "ERROR: Executable not found!"
    echo "Please build the application first:"
    echo ""
    echo "  cd $APP_DIR"
    echo "  source venv/bin/activate"
    echo "  pyinstaller bootloader.spec --clean"
    echo ""
    exit 1
fi

# Make executable runnable
chmod +x "$DIST_DIR/czar_bootloader"

# Create the desktop file
cat > /tmp/$DESKTOP_FILE << EOF
[Desktop Entry]
Name=CZAR Bootloader
Comment=Firmware Update Application for CZAR Displays
Exec=$DIST_DIR/czar_bootloader
Icon=$DIST_DIR/_internal/czar.png
Terminal=false
Type=Application
Categories=Utility;Development;
StartupNotify=true
EOF

# Copy to Desktop
cp /tmp/$DESKTOP_FILE ~/Desktop/$DESKTOP_FILE
chmod +x ~/Desktop/$DESKTOP_FILE

# Also install to applications menu
mkdir -p ~/.local/share/applications
cp /tmp/$DESKTOP_FILE ~/.local/share/applications/$DESKTOP_FILE

echo ""
echo "✓ Desktop icon installed!"
echo ""
echo "Double-click the icon to launch the application."
