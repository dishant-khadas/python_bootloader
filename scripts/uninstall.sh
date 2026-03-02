#!/bin/bash
# Uninstallation Script for CZAR Bootloader

set -e

# Configuration
APP_NAME="czar-bootloader"
INSTALL_DIR="/opt/$APP_NAME"
BIN_LINK="/usr/local/bin/$APP_NAME"
DESKTOP_FILE="/usr/share/applications/$APP_NAME.desktop"
ICON_FILE="/usr/share/pixmaps/$APP_NAME.png"

# Ensure script is run with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (use sudo)"
    exit 1
fi

echo "========================================="
echo "  Uninstalling CZAR Bootloader"
echo "========================================="

# 1. Remove installation directory
if [ -d "$INSTALL_DIR" ]; then
    echo "Removing $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
fi

# 2. Remove symlink
if [ -L "$BIN_LINK" ]; then
    echo "Removing symlink $BIN_LINK..."
    rm "$BIN_LINK"
fi

# 3. Remove desktop file
if [ -f "$DESKTOP_FILE" ]; then
    echo "Removing desktop entry $DESKTOP_FILE..."
    rm "$DESKTOP_FILE"
fi

# 4. Remove icon
if [ -f "$ICON_FILE" ]; then
    echo "Removing icon $ICON_FILE..."
    rm "$ICON_FILE"
fi

# 5. Refresh desktop database
if command -v update-desktop-database > /dev/null; then
    update-desktop-database /usr/share/applications
fi

echo "========================================="
echo "  Uninstallation Complete!"
echo "========================================="
