#!/bin/bash
# Install script for CZAR Bootloader desktop icon
# Run this on Raspberry Pi after building the executable

set -e

# Configuration - adjust these paths if needed
APP_DIR="/home/pi/python_bootloader/dist/czar_bootloader"
DESKTOP_FILE="czar_bootloader.desktop"

echo "Installing CZAR Bootloader desktop icon..."

# Check if the executable exists
if [ ! -f "$APP_DIR/czar_bootloader" ]; then
    echo "Error: Executable not found at $APP_DIR/czar_bootloader"
    echo "Please build the application first using: pyinstaller bootloader.spec"
    exit 1
fi

# Update the desktop file with correct paths
cat > /tmp/$DESKTOP_FILE << EOF
[Desktop Entry]
Name=CZAR Bootloader
Comment=Firmware Update Application for CZAR Displays
Exec=$APP_DIR/czar_bootloader
Icon=$APP_DIR/_internal/czar.png
Terminal=false
Type=Application
Categories=Utility;Development;
StartupNotify=true
EOF

# Copy to user's desktop
cp /tmp/$DESKTOP_FILE ~/Desktop/$DESKTOP_FILE

# Make it executable (required on some systems)
chmod +x ~/Desktop/$DESKTOP_FILE

# Also install to applications menu
mkdir -p ~/.local/share/applications
cp /tmp/$DESKTOP_FILE ~/.local/share/applications/$DESKTOP_FILE

echo ""
echo "✓ Desktop icon created at: ~/Desktop/$DESKTOP_FILE"
echo "✓ App menu entry created at: ~/.local/share/applications/$DESKTOP_FILE"
echo ""
echo "You may need to right-click the desktop icon and select"
echo "'Allow Launching' or 'Trust and Launch' on first use."
