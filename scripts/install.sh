#!/bin/bash
# Production Install Script for CZAR Bootloader
# This script moves the built application to /opt and sets up desktop integration.

set -e

# Configuration
APP_NAME="czar-bootloader"
DISPLAY_NAME="CZAR Bootloader"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$PROJECT_DIR/dist/czar_bootloader"
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
echo "  Installing $DISPLAY_NAME"
echo "========================================="

# 1. Verify build exists
if [ ! -d "$DIST_DIR" ]; then
    echo "Error: Build directory not found at $DIST_DIR"
    echo "Please run 'pyinstaller bootloader.spec' first."
    exit 1
fi

# 2. Preparation
echo "Step 1: Preparing installation directory..."
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# 3. Copy files to /opt
echo "Step 2: Copying build files to $INSTALL_DIR..."
cp -r "$DIST_DIR/." "$INSTALL_DIR/"

# 4. Set Permissions
echo "Step 3: Setting permissions..."
chown -R root:root "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/czar_bootloader"

# 5. Create absolute symlink
echo "Step 4: Creating system-wide symlink..."
ln -sf "$INSTALL_DIR/czar_bootloader" "$BIN_LINK"

# 6. Install Icon
echo "Step 5: Installing application icon..."
if [ -f "$PROJECT_DIR/assets/czar.png" ]; then
    cp "$PROJECT_DIR/assets/czar.png" "$ICON_FILE"
    chmod 644 "$ICON_FILE"
else
    echo "Warning: Icon not found in assets, skipping icon placement."
fi

# 7. Create Desktop Entry
echo "Step 6: Creating desktop integration..."
cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=$DISPLAY_NAME
Comment=Firmware Update Application for CZAR Displays
Exec=$BIN_LINK
Icon=$ICON_FILE
Terminal=false
Categories=Utility;Development;
StartupNotify=true
EOF

chmod 644 "$DESKTOP_FILE"

# 8. Refresh desktop database
if command -v update-desktop-database > /dev/null; then
    update-desktop-database /usr/share/applications
fi

echo "========================================="
echo "  Installation Complete!"
echo "========================================="
echo "You can now launch '$DISPLAY_NAME' from:"
echo "1. The Application Menu (Utilities/Development)"
echo "2. The terminal by typing: $APP_NAME"
echo "========================================="
