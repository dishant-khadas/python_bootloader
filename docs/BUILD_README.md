# CZAR Bootloader — Build & Deployment Guide

Complete guide to build the standalone executable, deploy it as a desktop application on Raspberry Pi OS 64-bit, and rebuild after code changes.

---

## Prerequisites

- Raspberry Pi 4 with Raspberry Pi OS 64-bit
- Python 3.7+ installed
- Internet connection (for cloning & installing packages)

---

## First-Time Setup

### Step 1: Clone the Repository

```bash
cd ~
mkdir -p app && cd app
git clone <your-repo-url> python_bootloader
cd python_bootloader
```

### Step 2: Create Virtual Environment & Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller
```

### Step 3: Configure Environment

Create a `.env` file in the project root with your configuration:

```bash
nano .env
```

Add your values (this file gets bundled into the executable):

```env
SERVER_URL=https://your-api-server.com/
DEVICE_ID=41999990
SERIAL_PORT=/dev/ttyAMA0
SERIAL_BAUD=115200
AES_KEY_HEX=your-64-char-hex-key
AES_IV_HEX=your-32-char-hex-iv
LOG_LEVEL=INFO
```

### Step 4: Set Serial/GPIO Permissions

```bash
sudo usermod -a -G dialout,gpio $USER
```

Reboot for this to take effect:

```bash
sudo reboot
```

---

## Building the Executable

### Step 5: Build with PyInstaller

```bash
cd ~/app/python_bootloader
source venv/bin/activate
pyinstaller bootloader.spec --clean --noconfirm
```

Build output will be in `dist/czar_bootloader/`. This takes several minutes on the Pi.

### Step 6: Test Before Installing

```bash
./dist/czar_bootloader/czar_bootloader
```

The application window should open. Close it once verified.

---

## Installing as Desktop Application

### Step 7: Run the Install Script

```bash
chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

**What this does:**

| Action | Location |
|--------|----------|
| Copies executable + assets | `/opt/czar-bootloader/` |
| Creates system symlink | `/usr/local/bin/czar-bootloader` |
| Installs app icon | `/usr/share/pixmaps/czar-bootloader.png` |
| Creates menu entry | `/usr/share/applications/czar-bootloader.desktop` |

### Step 8: Add Desktop Shortcut (Optional)

```bash
cp /usr/share/applications/czar-bootloader.desktop ~/Desktop/
chmod +x ~/Desktop/czar-bootloader.desktop
```

If the icon shows as untrusted, right-click it → **"Allow Launching"**.

### Step 9: Launch the App

Two ways:
1. **Application Menu** → Utilities/Development → **CZAR Bootloader**
2. **Terminal**: `czar-bootloader`

### Step 10: Delete the Repository (Optional)

Once everything works, you can delete the source code:

```bash
rm -rf ~/app/python_bootloader
```

The installed app in `/opt/czar-bootloader/` will continue to work independently.

---

## Rebuilding After Code Changes

When you make changes to the code and need to update the deployed app:

```bash
# 1. Navigate to the project
cd ~/app/python_bootloader

# 2. Pull latest code (if using git)
git pull origin main

# 3. Activate the virtual environment
source venv/bin/activate

# 4. Install any new dependencies (if requirements.txt changed)
pip install -r requirements.txt

# 5. Rebuild the executable
pyinstaller bootloader.spec --clean --noconfirm

# 6. Re-install to /opt (replaces the old version)
sudo ./scripts/install.sh
```

The desktop icon will automatically use the updated version — no need to recreate it.

---

## Uninstallation

To remove the application completely:

```bash
chmod +x scripts/uninstall.sh
sudo ./scripts/uninstall.sh
rm ~/Desktop/czar-bootloader.desktop  # if desktop shortcut exists
```

---

## File & Log Locations

| Item | Path |
|------|------|
| Executable & assets | `/opt/czar-bootloader/` |
| System symlink | `/usr/local/bin/czar-bootloader` |
| Desktop icon | `/usr/share/pixmaps/czar-bootloader.png` |
| Menu entry | `/usr/share/applications/czar-bootloader.desktop` |
| Application logs | `~/.czar-bootloader/bootloader.log` |
| Error logs | `~/.czar-bootloader/bootloader_errors.log` |
| Audit CSV logs | `~/.czar-bootloader/logs.csv` |
| Display logs | `~/.czar-bootloader/Display_log.csv` |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| App doesn't open from icon | Run from terminal to see error: `/opt/czar-bootloader/czar_bootloader 2>&1` |
| `ModuleNotFoundError` | Rebuild: `source venv/bin/activate && pip install -r requirements.txt && pyinstaller bootloader.spec --clean --noconfirm` |
| Serial port permission denied | `sudo usermod -a -G dialout $USER` then reboot |
| No logs appearing | Check `ls -la ~/.czar-bootloader/` — directory should exist after first run |
| Desktop icon says "untrusted" | Right-click the icon → **Allow Launching** |
| `Permission denied` on executable | `sudo chmod +x /opt/czar-bootloader/czar_bootloader` |
| Desktop icon says "invalid" | Ensure filename is `czar-bootloader.desktop` (dashes, not dots). Re-copy from `/usr/share/applications/` |
