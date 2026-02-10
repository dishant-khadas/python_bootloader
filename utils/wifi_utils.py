"""
WiFi Utilities Module for Python Bootloader Application.

This module provides cross-platform WiFi management functionality including
network scanning, connection, disconnection, and connectivity checking.

Platform Support:
    - Windows: Uses netsh wlan commands
    - Linux/Raspberry Pi: Uses nmcli (NetworkManager CLI)

Functions:
    scan_wifi: Scan for available WiFi networks.
    connect_wifi: Connect to a WiFi network with password.
    check_internet: Check if internet is available.
    disconnect_wifi: Disconnect from current WiFi network.
    wait_for_wifi_connected: Wait for connection to specific SSID.
    get_connected_ssid: Get the currently connected network name.
    has_ip: Check if device has a valid IP address.
"""

import subprocess
import platform
import time
import socket

# Platform detection for command selection
IS_WINDOWS = platform.system() == "Windows"


def scan_wifi() -> list[str]:
    """
    Scan for available WiFi networks.
    
    Uses platform-specific commands to discover nearby WiFi networks
    and returns a list of unique SSIDs.
    
    Returns:
        list[str]: List of available network SSIDs.
                   Returns error messages as list items on failure.
    """
    if IS_WINDOWS:
        try:
            # Run netsh command to scan WiFi networks
            output = subprocess.check_output(
                "netsh wlan show networks mode=bssid", 
                shell=True, 
                stderr=subprocess.STDOUT
            ).decode('utf-8', errors='ignore')
            
            # Parse SSIDs from output
            ssids = []
            for line in output.split('\n'):
                # Look for lines that start with "SSID"
                if line.strip().startswith('SSID') and ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        # Skip empty SSIDs and duplicates
                        if ssid and ssid not in ssids:
                            ssids.append(ssid)
            
            return ssids if ssids else ["No networks found"]
        except subprocess.CalledProcessError as e:
            print(f"Error scanning WiFi: {e}")
            return ["Error: WiFi adapter may be disabled"]
        except Exception as e:
            print(f"Unexpected error: {e}")
            return ["Error scanning networks"]
        
    # Linux/Raspberry Pi - use nmcli
    try:
        output = subprocess.check_output("nmcli -t -f SSID dev wifi", shell=True).decode()
        ssids = list({s.strip() for s in output.split("\n") if s.strip()})
        return ssids
    except:
        return []


def connect_wifi(ssid: str, password: str) -> bool:
    """
    Connect to a WiFi network with the given credentials.
    
    On Windows, creates a WiFi profile and connects using netsh.
    On Linux, uses nmcli to connect directly.
    
    Args:
        ssid (str): The network name to connect to.
        password (str): The network password.
        
    Returns:
        bool: True if connection command succeeded, False otherwise.
        
    Note:
        A True return doesn't guarantee internet connectivity.
        Use check_internet() to verify network access.
    """
    if IS_WINDOWS:
        try:
            # Create a WiFi profile XML
            profile_xml = f'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>'''
            
            # Save profile to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                profile_path = f.name
                f.write(profile_xml)
            
            try:
                # Delete existing profile if any
                subprocess.run(
                    f'netsh wlan delete profile name="{ssid}"',
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                # Add the profile
                subprocess.check_output(
                    f'netsh wlan add profile filename="{profile_path}"',
                    shell=True,
                    stderr=subprocess.STDOUT
                )
                
                # Connect to the network
                result = subprocess.run(
                    f'netsh wlan connect name="{ssid}"',
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # Wait a bit for connection to establish
                time.sleep(3)
                
                return result.returncode == 0
            finally:
                # Clean up temp file
                import os
                try:
                    os.unlink(profile_path)
                except:
                    pass
                    
        except Exception as e:
            print(f"Error connecting to WiFi: {e}")
            return False

    # Linux/Raspberry Pi - use nmcli
    try:
        # Delete existing connection profile if any
        subprocess.run(
            ["nmcli", "connection", "delete", ssid],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        cmd = f"nmcli dev wifi connect '{ssid}' password '{password}'"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except:
        return False


def check_internet() -> bool:
    """
    Check if internet connectivity is available.
    
    Pings Google DNS (8.8.8.8) to verify internet access.
    
    Returns:
        bool: True if internet is available, False otherwise.
    """
    try:
        if IS_WINDOWS:
            # Windows ping uses -n for count
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "3000", "8.8.8.8"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            # Linux ping uses -c for count, -W for timeout in seconds
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "3", "8.8.8.8"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        return result.returncode == 0
    except Exception:
        return False


def disconnect_wifi() -> None:
    """
    Disconnect from the current WiFi network.
    
    Uses platform-specific commands to disconnect from the
    currently connected WiFi network.
    """
    try:
        if platform.system() == "Windows":
            subprocess.run(["netsh", "wlan", "disconnect"], capture_output=True, text=True)
        else:
            subprocess.run(["nmcli", "dev", "disconnect", "wlan0"], capture_output=True, text=True)
    except Exception:
        pass


def wait_for_wifi_connected(ssid: str, timeout: int = 15) -> bool:
    """
    Wait for WiFi connection to a specific network.
    
    Polls the WiFi connection status until either the target
    network is connected or the timeout is reached.
    
    Args:
        ssid (str): The network name to wait for.
        timeout (int): Maximum wait time in seconds. Default is 15.
        
    Returns:
        bool: True if connected to the specified SSID, False if timeout.
    """
    start = time.time()
    target = (ssid or "").strip().lower()
    
    while time.time() - start < timeout:
        try:
            if IS_WINDOWS:
                out = subprocess.check_output(
                    "netsh wlan show interfaces",
                    shell=True,
                    text=True,
                    errors="ignore"
                ).lower()
                
                if "state" in out and "connected" in out:
                    if "ssid" in out and target in out:
                        return True
                    
                if "state" in out and "disconnected" in out:
                    return False
            else:
                # Linux/Raspberry Pi - use nmcli
                out = subprocess.check_output(
                    ["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"],
                    text=True,
                    errors="ignore"
                ).strip()
                for line in out.splitlines():
                    if line.startswith("yes:"):
                        current_ssid = line.split("yes:", 1)[1].strip().lower()
                        if current_ssid == target:
                            return True
        except Exception:
            pass
        
        time.sleep(0.5)
        
    return False


def get_connected_ssid() -> str | None:
    """
    Get the currently connected WiFi network name.
    
    Returns:
        str | None: The SSID of the connected network, or None if not connected.
    """
    if IS_WINDOWS:
        try:
            # Get current WiFi connection info
            output = subprocess.check_output(
                "netsh wlan show interfaces",
                shell=True,
                stderr=subprocess.STDOUT
            ).decode('utf-8', errors='ignore')
            
            # Look for SSID in the output
            for line in output.split('\n'):
                if 'SSID' in line and ':' in line and 'BSSID' not in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        if ssid:
                            return ssid
            return None
        except Exception as e:
            print(f"Error getting connected SSID: {e}")
            return None 

    # Linux/Raspberry Pi - use nmcli
    try:
        result = subprocess.check_output(
            "nmcli -t -f ACTIVE,SSID dev wifi", shell=True
        ).decode().split("\n")

        for line in result:
            if line.startswith("yes:"):
                return line.split(":")[1]
        return None
    except:
        return None


def has_ip() -> bool:
    """
    Check if the device has a valid (non-localhost) IP address.
    
    Uses a socket connection to detect the assigned IP address
    and verifies it's not a localhost address.
    
    Returns:
        bool: True if device has a valid IP, False otherwise.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return bool(ip) and not ip.startswith("127.")
    except:
        return False

