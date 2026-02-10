# CZAR Bootloader - Deployment Guide

## Quick Update (After Code Changes)

On your Raspberry Pi, run:
```bash
cd /home/czar/app/python_bootloader
git pull origin main
```

That's it! Click the desktop icon to run the latest version.

---

## If New Python Packages Were Added

```bash
cd /home/czar/app/python_bootloader
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
```

---

## First Time Setup

### 1. Clone the Repository
```bash
cd /home/czar/app
git clone <repository-url> python_bootloader
cd python_bootloader
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
cp .env.example .env
nano .env
# Set SERVER_URL, DEVICE_ID, SERIAL_PORT etc.
```

### 4. Install Desktop Icon
```bash
chmod +x czar_launcher.sh
cp czar_bootloader.desktop ~/Desktop/
chmod +x ~/Desktop/czar_bootloader.desktop
```

### 5. Test
Double-click the desktop icon or run:
```bash
source venv/bin/activate
python main.py
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied on serial port | `sudo usermod -a -G dialout czar` then reboot |
| Module not found | `source venv/bin/activate && pip install -r requirements.txt` |
| Desktop icon shows X | Check paths in `czar_bootloader.desktop` |
| SERVER_URL not set | Check `.env` file exists with correct values |
