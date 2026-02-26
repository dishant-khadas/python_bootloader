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

## Production Deployment

After building the executable, follow these steps to integrate the application into Raspberry Pi OS as a standard desktop application.

### Step 9: Install to System
The application should be moved to `/opt` for production use. We have provided an install script to automate this.

```bash
sudo ./scripts/install.sh
```

**What this script does:**
1.  Moves the executable to `/opt/czar-bootloader` (standard for 3rd party apps).
2.  Sets proper root ownership and execution permissions.
3.  Creates a system-wide symlink at `/usr/local/bin/czar-bootloader`.
4.  Installs the application icon to `/usr/share/pixmaps/`.
5.  Creates a `.desktop` file in `/usr/share/applications/` to register the app in the system menu.

---

### Step 10: Launching the Application
Once installed, you can launch the application in two ways:
1.  **Desktop Menu**: Go to the Raspberry Pi Application Menu -> **Utilities** or **Development** -> **CZAR Bootloader**.
2.  **Command Line**: Open a terminal and simply type:
    ```bash
    czar-bootloader
    ```

---

### Uninstallation
To cleanly remove the application and its integration from the system:

```bash
sudo ./scripts/uninstall.sh
```

---

## Directory Structure (Standard Locations)
Following Linux best practices (FHS):
*   **Binary & Assets**: `/opt/czar-bootloader/`
*   **System Symlink**: `/usr/local/bin/czar-bootloader`
*   **Desktop Icon**: `/usr/share/pixmaps/czar-bootloader.png`
*   **Menu Entry**: `/usr/share/applications/czar-bootloader.desktop`

---

## Troubleshooting

### Permissions for Serial/GPIO
The application typically needs access to hardware. Ensure your user is in the `dialout` and `gpio` groups:
```bash
sudo usermod -a -G dialout,gpio $USER
```
*Note: You may need to logout and log back in for group changes to take effect.*

### Permission Denied
If the app fails to start, ensure the installed binary is executable:
```bash
sudo chmod +x /opt/czar-bootloader/czar_bootloader
```

