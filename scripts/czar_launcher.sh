#!/bin/bash
# Launcher script for CZAR Bootloader
# This runs the app using the virtual environment

# Set up the environment properly
export HOME=/home/czar
export USER=czar
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
export DISPLAY="${DISPLAY:-:0}"

# Change to the application directory
APP_DIR="/home/czar/app/python_bootloader"
cd "$APP_DIR"

# Log file for debugging (optional - can be removed later)
# LOG_FILE="$APP_DIR/app.log"

# Activate virtual environment
source venv/bin/activate

# Run the application with output logging
exec python main.py 2>&1 | tee -a "$LOG_FILE"
