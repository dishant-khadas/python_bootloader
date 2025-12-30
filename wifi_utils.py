import subprocess
import platform
import time

IS_WINDOWS = platform.system() == "Windows"

def scan_wifi():
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
        
    try:
        output = subprocess.check_output("nmcli -t -f SSID dev wifi", shell=True).decode()
        ssids = list({s.strip() for s in output.split("\n") if s.strip()})
        return ssids
    except:
        return []

def connect_wifi(ssid, password):
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

    try:
        cmd = f"nmcli dev wifi connect '{ssid}' password '{password}'"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except:
        return False

def check_internet():
    if IS_WINDOWS:
        print("[MOCK] Checking internet connection...")
        time.sleep(1)
        return True

    try:
        subprocess.check_output("ping -c 1 8.8.8.8", shell=True)
        return True
    except:
        return False

def get_connected_ssid():
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
