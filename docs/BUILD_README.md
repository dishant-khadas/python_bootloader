# CZAR Bootloader - Build Instructions

## Prerequisites
- Raspberry Pi 4 with Raspberry Pi OS
- Python 3.7+ installed
- Internet connection for downloading dependencies

---

## Step-by-Step Build Guide

### Step 1: Transfer Project to Raspberry Pi
Copy the entire `python_bootloader` folder to your Raspberry Pi.

```bash
# From your PC (example using scp):
scp -r /path/to/python_bootloader pi@<raspberry-pi-ip>:~/
```

---

### Step 2: SSH into Raspberry Pi
```bash
ssh pi@<raspberry-pi-ip>
cd ~/python_bootloader
```

---

### Step 3: Create Virtual Environment
```bash
python3 -m venv venv
```

---

### Step 4: Activate Virtual Environment
```bash
source venv/bin/activate
```

---

### Step 5: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller
```

---

### Step 6: Make Build Script Executable (Optional)
```bash
chmod +x build.sh run.sh
```

---

### Step 7: Build the Executable
```bash
pyinstaller bootloader.spec --clean
```

This will take several minutes. The output will be in `dist/czar_bootloader/`

---

### Step 8: Test the Executable
```bash
cd dist/czar_bootloader
./czar_bootloader
```

---

## Distribution

To deploy on another Raspberry Pi:
1. Copy the entire `dist/czar_bootloader/` folder
2. Make sure `.env` file is present with correct configuration
3. Run `./czar_bootloader`

---

## Troubleshooting

### "No module named X" error
Add the missing module to `hiddenimports` in `bootloader.spec` and rebuild.

### GUI doesn't appear
Set `console=True` in `bootloader.spec` to see error messages.

### Permission denied for serial/GPIO
Run with sudo: `sudo ./czar_bootloader`
