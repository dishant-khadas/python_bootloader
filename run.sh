#!/bin/bash
# Run script for CZAR Bootloader Application
# This script runs the built executable

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTLOADER_DIR="$SCRIPT_DIR/dist/czar_bootloader"

if [ ! -d "$BOOTLOADER_DIR" ]; then
    echo "Error: Executable not found. Please run build.sh first."
    exit 1
fi

cd "$BOOTLOADER_DIR"
./czar_bootloader "$@"
