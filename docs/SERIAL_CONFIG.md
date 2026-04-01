# Raspberry Pi Serial Port Configuration (Using /dev/ttyAMA0)

By default, the high-performance PL011 UART (`/dev/ttyAMA0`) is used by the Bluetooth module on Raspberry Pi 4. To use it on the GPIO pins (TX: GPIO14, RX: GPIO15), you must disable Bluetooth.

## 1. Modify Boot Configuration

Open the boot configuration file:
- On Raspberry Pi OS **Bookworm**: `sudo nano /boot/firmware/config.txt`
- On **Older versions**: `sudo nano /boot/config.txt`

Add the following lines to the end of the file:
```ini
# Disable Bluetooth to use /dev/ttyAMA0 on GPIO pins
dtoverlay=disable-bt
```

## 2. Disable Bluetooth Services

Run these commands in the terminal to stop the Bluetooth services from starting:
```bash
sudo systemctl disable hciuart
sudo systemctl mask bluetooth.service
```

## 3. Disable Serial Console (If enabled)

Ensure the serial console is NOT using the port:
```bash
sudo raspi-config
```
1. Select **Interface Options** -> **Serial Port**.
2. Select **No** to "login shell accessible over serial".
3. Select **Yes** to "serial port hardware enabled".

## 4. Reboot

You must reboot for the changes to take effect:
```bash
sudo reboot
```

### Troubleshooting: Permissions & Groups
If `ls -l /dev/ttyAMA0` shows `crw-------` (root-only access), the serial console is likely still enabled or the user lacks group permissions. fix it with:

```bash
# 1. Disable serial console (freew the port)
sudo raspi-config nonint do_serial_cons 1

# 2. Add user to dialout/gpio groups
sudo usermod -a -G dialout,gpio $USER

# 3. REBOOT
sudo reboot
```

## 5. Verify

After rebooting, verify that `/dev/ttyAMA0` exists and is available:
```bash
ls -l /dev/ttyAMA0
```
Then update your `.env` file to use it:
```env
SERIAL_PORT=/dev/ttyAMA0
```
