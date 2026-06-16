#!/bin/bash
# Unified Setup & Installation Script for CZAR Bootloader
# Auto-configures dependencies, permissions, virtual environment, and builds the app.
# Run this script as a NORMAL user (non-root).

set -e

# Terminal colors for premium look
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}======================================================${NC}"
echo -e "${CYAN}       CZAR Bootloader Unified Installer Setup        ${NC}"
echo -e "${CYAN}======================================================${NC}"

# 1. Ensure the script is NOT run as root/sudo directly
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}Error: Please DO NOT run this script directly as root or with sudo.${NC}"
    echo -e "Run it as a normal user: ${GREEN}./setup.sh${NC}"
    echo -e "The script will prompt for your password via sudo when needed."
    exit 1
fi

# 2. Get project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 3. Check for Python3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python3 is not installed on this system.${NC}"
    exit 1
fi

# 4. Install system dependencies (requires sudo)
echo -e "\n${BLUE}[1/7] Installing system dependencies (requires sudo)...${NC}"
sudo apt update
sudo apt install -y python3-lgpio python3-pil.imagetk python3-tk

# 5. Configure hardware access permissions (requires sudo)
echo -e "\n${BLUE}[2/8] Configuring serial and GPIO group permissions...${NC}"
sudo usermod -a -G dialout,gpio "$USER"
echo -e "${GREEN}Added user '$USER' to 'dialout' and 'gpio' groups.${NC}"

# 6. Configure hardware serial port and raspi-config settings (requires sudo)
echo -e "\n${BLUE}[3/8] Configuring serial port and disabling Bluetooth console (requires sudo)...${NC}"

# 6a. Disable Bluetooth to free up /dev/ttyAMA0 on GPIO pins
BOOT_CONFIG=""
if [ -f "/boot/firmware/config.txt" ]; then
    BOOT_CONFIG="/boot/firmware/config.txt"
elif [ -f "/boot/config.txt" ]; then
    BOOT_CONFIG="/boot/config.txt"
fi

if [ -n "$BOOT_CONFIG" ]; then
    echo -e "Detecting boot configuration at $BOOT_CONFIG..."
    if ! grep -q "dtoverlay=disable-bt" "$BOOT_CONFIG"; then
        echo -e "Adding ${YELLOW}dtoverlay=disable-bt${NC} overlay to disable Bluetooth..."
        echo -e "\n# Disable Bluetooth to use /dev/ttyAMA0 on GPIO pins\ndtoverlay=disable-bt" | sudo tee -a "$BOOT_CONFIG"
        echo -e "${GREEN}Added dtoverlay=disable-bt configuration.${NC}"
    else
        echo -e "${GREEN}dtoverlay=disable-bt is already configured in $BOOT_CONFIG.${NC}"
    fi

    # Disable bluetooth services
    echo -e "Disabling Bluetooth services to free the serial port..."
    sudo systemctl disable hciuart || true
    sudo systemctl mask bluetooth.service || true
fi

# 6b. Configure serial console via raspi-config
if command -v raspi-config &> /dev/null; then
    echo -e "Configuring Raspberry Pi Serial Port settings via raspi-config..."
    # Disable login shell over serial (do_serial_cons 1)
    sudo raspi-config nonint do_serial_cons 1
    # Enable hardware serial interface (do_serial_hw 0)
    sudo raspi-config nonint do_serial_hw 0
    echo -e "${GREEN}raspi-config serial settings updated: Console shell disabled, hardware UART enabled.${NC}"
else
    echo -e "${YELLOW}raspi-config utility not found. Skipping Raspberry Pi OS-specific configuration.${NC}"
fi

# 7. Configure Environment File (.env)
echo -e "\n${BLUE}[4/8] Setting up environment configuration (.env)...${NC}"

# Helper function to prompt user with a default value
prompt_default() {
    local prompt_text="$1"
    local default_val="$2"
    local var_name="$3"
    
    # Read user input
    read -p "$(echo -e "${CYAN}${prompt_text}${NC} [${YELLOW}${default_val}${NC}]: ")" input_val
    
    # If empty, use default
    if [ -z "$input_val" ]; then
        eval "$var_name=\"$default_val\""
    else
        eval "$var_name=\"$input_val\""
    fi
}

echo -e "Please configure the application parameters (Press Enter to keep the default value):"

prompt_default "Device ID" "41999990" DEVICE_ID
prompt_default "Server URL" "https://bootloader.czarmetricsystem.com/" SERVER_URL
prompt_default "Bootloader Detect GPIO Pin (BL_DETECT_PIN)" "17" BL_DETECT_PIN
prompt_default "Display Power GPIO Pin (DISPLAY_ON_PIN)" "27" DISPLAY_ON_PIN
prompt_default "AES Key Hex" "603de52c073b6108d72d9810a30914dff4be2b73aef0857d77811f3" AES_KEY_HEX
prompt_default "AES IV Hex" "2ef451f1de828d2a662a9fc34728d2a66" AES_IV_HEX
prompt_default "AWS Access Key ID" "AKIIBOYBOFJ5V6XDIBOY" AWS_ACCESS_KEY_ID
prompt_default "AWS Secret Access Key" "Yde0quTcvidpFxrX0ibB1r2rVVhdfhkjuerh" AWS_SECRET_ACCESS_KEY

# Write user settings to .env
cat > .env << EOF
# Environment Configuration
SERVER_URL=$SERVER_URL
DEVICE_ID=$DEVICE_ID

# Serial Port Configuration
SERIAL_PORT=/dev/ttyAMA0
SERIAL_BAUD=115200
SERIAL_TIMEOUT=15

# GPIO Configuration
GPIOCHIP=gpiochip4
BL_DETECT_PIN=$BL_DETECT_PIN
DISPLAY_ON_PIN=$DISPLAY_ON_PIN

# Handshake Configuration
HANDSHAKE_TIMEOUT=10

# Encryption Keys
AES_KEY_HEX=$AES_KEY_HEX
AES_IV_HEX=$AES_IV_HEX

# AWS Credentials for Key Retrieval
AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY

# Logging Level
LOG_LEVEL=INFO
EOF

echo -e "${GREEN}.env configuration file created and updated successfully!${NC}"

# 8. Setup Python Virtual Environment and dependencies
echo -e "\n${BLUE}[5/8] Creating virtual environment...${NC}"
if [ -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment 'venv' already exists. Cleaning up...${NC}"
    rm -rf venv
fi
python3 -m venv --system-site-packages venv

echo -e "\n${BLUE}[6/8] Installing python requirements inside venv...${NC}"
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate

# 9. Build the application executable
echo -e "\n${BLUE}[7/8] Building standalone executable with PyInstaller...${NC}"
source venv/bin/activate
pyinstaller bootloader.spec --clean --noconfirm
deactivate
echo -e "${GREEN}Executable built successfully inside dist/czar_bootloader/${NC}"

# 10. Deploy application to /opt (requires sudo)
echo -e "\n${BLUE}[8/8] Deploys application to system (/opt)...${NC}"
chmod +x scripts/install.sh
sudo ./scripts/install.sh

# 11. Copy Desktop Shortcut (Optional)
if [ -d "$HOME/Desktop" ]; then
    echo -e "\n${BLUE}Adding Desktop Shortcut...${NC}"
    cp /usr/share/applications/czar-bootloader.desktop "$HOME/Desktop/"
    chmod +x "$HOME/Desktop/czar-bootloader.desktop"
    echo -e "${GREEN}Desktop shortcut created at ~/Desktop/czar-bootloader.desktop${NC}"
fi

# 12. Final output and reboot prompt
echo -e "\n${CYAN}======================================================${NC}"
echo -e "${GREEN}        Installation & Configuration Completed!       ${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "\n${RED}CRITICAL REBOOT REQUIRED:${NC}"
echo -e "You must reboot the device now for serial, Bluetooth overlays, and GPIO access"
echo -e "permissions to take effect."
echo -e "Run the following command to reboot:"
echo -e "    ${YELLOW}sudo reboot${NC}\n"
echo -e "${CYAN}======================================================${NC}"
