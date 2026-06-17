#!/bin/bash
# Rebuild & Deploy Script for CZAR Bootloader
# Run this script after making code changes to recompile the executable and deploy it.
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
echo -e "${CYAN}       CZAR Bootloader Rebuild & Update Tool          ${NC}"
echo -e "${CYAN}======================================================${NC}"

# 1. Ensure the script is NOT run as root/sudo directly
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}Error: Please DO NOT run this script directly as root or with sudo.${NC}"
    echo -e "Run it as a normal user: ${GREEN}./update_build.sh${NC}"
    echo -e "The script will prompt for your password via sudo when deploying."
    exit 1
fi

# 2. Get project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 3. Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${RED}Error: Virtual environment 'venv' not found.${NC}"
    echo -e "Please run the full installer first: ${YELLOW}./setup.sh${NC}"
    exit 1
fi

# 4. Activate virtual environment and rebuild
echo -e "\n${BLUE}[1/2] Rebuilding executable with PyInstaller...${NC}"
source venv/bin/activate

if ! command -v pyinstaller &> /dev/null; then
    echo -e "${YELLOW}PyInstaller not found in virtual environment. Installing...${NC}"
    pip install pyinstaller
fi

# Run compilation
pyinstaller bootloader.spec --clean --noconfirm
deactivate

echo -e "${GREEN}Executable rebuilt successfully inside dist/czar_bootloader/${NC}"

# 5. Prompt user to deploy/install the updated build to /opt
echo -e "\n${BLUE}[2/2] Deploying updated build to system (/opt)...${NC}"
read -p "$(echo -e "${CYAN}Do you want to deploy this update system-wide now? (y/n)${NC} [y]: ")" deploy_choice
deploy_choice=${deploy_choice:-y}

if [[ "$deploy_choice" =~ ^[Yy]$ ]]; then
    if [ -f "scripts/install.sh" ]; then
        chmod +x scripts/install.sh
        echo -e "${YELLOW}Running production installer (requires sudo)...${NC}"
        sudo ./scripts/install.sh
        echo -e "${GREEN}System-wide deployment updated successfully!${NC}"
    else
        echo -e "${RED}Error: scripts/install.sh not found. Cannot deploy.${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}Deployment skipped. The new build is available in dist/czar_bootloader/ but not copied to /opt.${NC}"
fi

echo -e "\n${CYAN}======================================================${NC}"
echo -e "${GREEN}             Rebuild Process Completed!               ${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "Launch the application using the Desktop Icon or by running: ${YELLOW}czar-bootloader${NC}\n"
