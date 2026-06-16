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
echo -e "\n${BLUE}[2/7] Configuring serial and GPIO group permissions...${NC}"
sudo usermod -a -G dialout,gpio "$USER"
echo -e "${GREEN}Added user '$USER' to 'dialout' and 'gpio' groups.${NC}"

# 6. Configure Environment File (.env)
echo -e "\n${BLUE}[3/7] Setting up environment configuration (.env)...${NC}"
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${GREEN}Created .env from .env.example template.${NC}"
        echo -e "${YELLOW}Warning: Please edit the .env file later to match your server/device settings.${NC}"
    else
        echo -e "${YELLOW}Warning: .env.example not found. Creating empty .env file...${NC}"
        touch .env
    fi
else
    echo -e "${GREEN}.env configuration file already exists. Skipping setup.${NC}"
fi

# 7. Setup Python Virtual Environment and dependencies
echo -e "\n${BLUE}[4/7] Creating virtual environment...${NC}"
if [ -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment 'venv' already exists. Cleaning up...${NC}"
    rm -rf venv
fi
python3 -m venv --system-site-packages venv

echo -e "\n${BLUE}[5/7] Installing python requirements inside venv...${NC}"
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate

# 8. Build the application executable
echo -e "\n${BLUE}[6/7] Building standalone executable with PyInstaller...${NC}"
source venv/bin/activate
pyinstaller bootloader.spec --clean --noconfirm
deactivate
echo -e "${GREEN}Executable built successfully inside dist/czar_bootloader/${NC}"

# 9. Deploy application to /opt (requires sudo)
echo -e "\n${BLUE}[7/7] Deploys application to system (/opt)...${NC}"
chmod +x scripts/install.sh
sudo ./scripts/install.sh

# 10. Copy Desktop Shortcut (Optional)
if [ -d "$HOME/Desktop" ]; then
    echo -e "\n${BLUE}Adding Desktop Shortcut...${NC}"
    cp /usr/share/applications/czar-bootloader.desktop "$HOME/Desktop/"
    chmod +x "$HOME/Desktop/czar-bootloader.desktop"
    echo -e "${GREEN}Desktop shortcut created at ~/Desktop/czar-bootloader.desktop${NC}"
fi

# 11. Final output and reboot prompt
echo -e "\n${CYAN}======================================================${NC}"
echo -e "${GREEN}        Installation Completed Successfully!          ${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "\n${RED}CRITICAL STEP REQUIRED:${NC}"
echo -e "You must reboot the device now for serial and GPIO access permissions to apply."
echo -e "Run the following command to reboot:"
echo -e "    ${YELLOW}sudo reboot${NC}\n"
echo -e "${CYAN}======================================================${NC}"
