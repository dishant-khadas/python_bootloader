#!/bin/bash
# Unified Uninstallation Script for CZAR Bootloader
# Safely removes application folders, configurations, logs, virtual environments, and restores serial settings.
# Run this script as a NORMAL user (non-root).

set -e

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}======================================================${NC}"
echo -e "${CYAN}       CZAR Bootloader Unified Uninstaller            ${NC}"
echo -e "${CYAN}======================================================${NC}"

# 1. Ensure the script is NOT run as root/sudo directly
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}Error: Please DO NOT run this script directly as root or with sudo.${NC}"
    echo -e "Run it as a normal user: ${GREEN}./uninstall.sh${NC}"
    echo -e "The script will prompt for your password via sudo when needed."
    exit 1
fi

# Confirm uninstallation
read -p "$(echo -e "${YELLOW}Are you sure you want to completely uninstall the CZAR Bootloader application? (y/N): ${NC}")" confirm
if [[ ! "$confirm" =~ ^[yY]$ ]]; then
    echo -e "${BLUE}Uninstallation cancelled.${NC}"
    exit 0
fi

# 2. Get project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 3. System-wide cleanup (requires sudo)
echo -e "\n${BLUE}[1/6] Removing system-wide installation and desktop files (requires sudo)...${NC}"
if [ -f "scripts/uninstall.sh" ]; then
    chmod +x scripts/uninstall.sh
    sudo ./scripts/uninstall.sh
else
    # Fallback cleanup if scripts/uninstall.sh is missing
    echo -e "${YELLOW}scripts/uninstall.sh not found. Performing manual system cleanup...${NC}"
    sudo rm -rf /opt/czar-bootloader
    sudo rm -f /usr/local/bin/czar-bootloader
    sudo rm -f /usr/share/applications/czar-bootloader.desktop
    sudo rm -f /usr/share/pixmaps/czar-bootloader.png
    if command -v update-desktop-database &> /dev/null; then
        sudo update-desktop-database /usr/share/applications
    fi
fi

# 4. Remove Desktop Shortcut
echo -e "\n${BLUE}[2/6] Cleaning up Desktop shortcuts...${NC}"
if [ -f "$HOME/Desktop/czar-bootloader.desktop" ]; then
    rm -f "$HOME/Desktop/czar-bootloader.desktop"
    echo -e "${GREEN}Removed ~/Desktop/czar-bootloader.desktop shortcut.${NC}"
else
    echo -e "${GREEN}No desktop shortcut found to remove.${NC}"
fi

# 5. Clean up local configuration (.env)
echo -e "\n${BLUE}[3/6] Cleaning up local configuration...${NC}"
read -p "$(echo -e "Do you want to delete the configuration ${YELLOW}.env${NC} file? (y/N): ")" remove_env
if [[ "$remove_env" =~ ^[yY]$ ]]; then
    rm -f .env
    echo -e "${GREEN}Removed .env configuration file.${NC}"
else
    echo -e "${GREEN}Kept .env configuration file.${NC}"
fi

# 6. Clean up virtual environment and build folders
echo -e "\n${BLUE}[4/6] Cleaning up build and virtual environment directories...${NC}"
read -p "$(echo -e "Do you want to delete the Python virtual environment (venv) and build artifacts (build, dist)? (y/N): ")" remove_builds
if [[ "$remove_builds" =~ ^[yY]$ ]]; then
    rm -rf venv build dist
    echo -e "${GREEN}Removed venv, build, and dist directories.${NC}"
else
    echo -e "${GREEN}Kept virtual environment and build files.${NC}"
fi

# 7. Clean up application logs/database
echo -e "\n${BLUE}[5/6] Cleaning up application data and database logs...${NC}"
read -p "$(echo -e "Do you want to delete all log files and database under ${YELLOW}~/.czar-bootloader/${NC}? (y/N): ")" remove_logs
if [[ "$remove_logs" =~ ^[yY]$ ]]; then
    rm -rf "$HOME/.czar-bootloader"
    echo -e "${GREEN}Removed ~/.czar-bootloader/ directory.${NC}"
else
    echo -e "${GREEN}Kept log and database directory.${NC}"
fi

# 8. Restore Bluetooth and Serial Boot configuration (requires sudo)
REBOOT_NEEDED=false
echo -e "\n${BLUE}[6/6] Restoring Raspberry Pi Serial/Bluetooth configuration...${NC}"
read -p "$(echo -e "Do you want to re-enable Bluetooth and restore default serial settings? (y/N): ")" restore_bt
if [[ "$restore_bt" =~ ^[yY]$ ]]; then
    BOOT_CONFIG=""
    if [ -f "/boot/firmware/config.txt" ]; then
        BOOT_CONFIG="/boot/firmware/config.txt"
    elif [ -f "/boot/config.txt" ]; then
        BOOT_CONFIG="/boot/config.txt"
    fi

    if [ -n "$BOOT_CONFIG" ]; then
        echo -e "Modifying boot settings at $BOOT_CONFIG..."
        # Remove dtoverlay=disable-bt and the preceding comment
        sudo sed -i '/# Disable Bluetooth to use \/dev\/ttyAMA0 on GPIO pins/d' "$BOOT_CONFIG"
        sudo sed -i '/dtoverlay=disable-bt/d' "$BOOT_CONFIG"
        echo -e "${GREEN}Removed Bluetooth disabling overlay from $BOOT_CONFIG.${NC}"
        REBOOT_NEEDED=true
    fi

    # Re-enable and unmask bluetooth services
    echo -e "Re-enabling and starting Bluetooth services..."
    sudo systemctl unmask bluetooth.service || true
    sudo systemctl enable hciuart || true
    sudo systemctl enable bluetooth.service || true
    sudo systemctl start bluetooth.service || true
    
    # Re-enable login console over serial port (default Pi behavior)
    if command -v raspi-config &> /dev/null; then
        sudo raspi-config nonint do_serial_cons 0
        echo -e "${GREEN}raspi-config updated: Serial login console re-enabled.${NC}"
        REBOOT_NEEDED=true
    fi
    echo -e "${GREEN}Bluetooth and Serial configurations restored.${NC}"
else
    echo -e "${GREEN}Skipped serial and Bluetooth restoration.${NC}"
fi

# 9. Finished
echo -e "\n${CYAN}======================================================${NC}"
echo -e "${GREEN}        Uninstallation Completed Successfully!        ${NC}"
echo -e "${CYAN}======================================================${NC}"

if [ "$REBOOT_NEEDED" = true ]; then
    echo -e "\n${RED}NOTICE:${NC}"
    echo -e "Since Bluetooth and Serial settings were restored, you must reboot."
    echo -e "Run the following command to reboot:"
    echo -e "    ${YELLOW}sudo reboot${NC}\n"
    echo -e "${CYAN}======================================================${NC}"
fi
