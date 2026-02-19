"""
System Utilities for Python Bootloader Application.

Provides shell command execution, WiFi connectivity management,
internet connectivity checks, and time conversion utilities.
Previously part of the monolithic du_utils.py.

Functions:
    exec_command: Execute a shell command safely.
    run_commands: Execute WiFi connection commands via nmcli.
    check_connection: Check internet connectivity.
    convert_seconds: Convert seconds to hours/minutes/seconds.
"""

import subprocess
import requests
from utils.logger import logger


def exec_command(command: str | list[str], ssid: str | None = None, use_array: bool = False) -> str:
    """
    Execute a shell command and return stdout.
    
    SECURITY NOTE: Prefer use_array=True with list commands to prevent injection attacks.
    
    Args:
        command (str | list[str]): Shell command string or array of command parts.
        ssid (str, optional): SSID for WiFi connection success detection.
        use_array (bool): If True, command must be a list and shell=False is used.
        
    Returns:
        str: Command stdout output.
        
    Raises:
        subprocess.CalledProcessError: If command fails.
        
    Examples:
        # Safe array-based command (prevents injection)
        exec_command(["nmcli", "device", "wifi", "connect", "MyWiFi", "password", "pass123"], use_array=True)
        
        # Legacy string command (only for static commands without user input)
        exec_command("nmcli radio wifi on")
    """
    try:
        logger.debug(f"Running: {command if isinstance(command, str) else ' '.join(command)}")
        
        if use_array and isinstance(command, list):
            # SECURE: Array-based command with shell=False prevents injection
            completed = subprocess.run(command, shell=False, check=True, capture_output=True, text=True)
        elif isinstance(command, str):
            # Legacy mode: Only use for static commands without user input
            completed = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        else:
            raise ValueError("Invalid command type. use_array=True requires list command.")
            
        out = completed.stdout
        
        # Detect WiFi connection success
        if ssid and ("successfully activated" in out or "successfully activated" in completed.stdout.lower()):
            logger.info(f"Connection Success {ssid}")
        return out
    except subprocess.CalledProcessError as e:
        stderr = e.stderr or ""
        if "No network" in stderr:
            logger.warning("Unable to find network")
        raise


def run_commands(values: dict) -> str:
    """
    Execute WiFi connection commands via nmcli.
    
    Enables WiFi radio, scans for networks, and connects to the
    specified network with the provided password.
    
    Args:
        values (dict): Dictionary with 'ssid' and 'password' keys.
        
    Returns:
        str: Command output on success.
        
    Raises:
        Exception: If any WiFi command fails.
    """
    wifi_ssid = values.get("ssid")
    password = values.get("password")
    try:
        exec_command("nmcli radio wifi on")
        exec_command("nmcli device wifi list")
        # SECURITY FIX: Use array-based command instead of shell=True to prevent injection
        out = exec_command(
            ["nmcli", "device", "wifi", "connect", wifi_ssid, "password", password],
            ssid=wifi_ssid,
            use_array=True
        )
        return out
    except Exception as e:
        logger.error(f"run_commands error: {e}")
        raise


def check_connection(timeout: int = 5) -> bool:
    """
    Check internet connectivity by connecting to Google.
    
    Args:
        timeout (int): Request timeout in seconds. Default is 5.
        
    Returns:
        bool: True if internet is available, False otherwise.
    """
    try:
        resp = requests.get("https://www.google.com", timeout=timeout)
        return resp.status_code == 200
    except Exception as e:
        logger.info(f"No Internet Connection: {e}")
        return False


def convert_seconds(total_seconds: int) -> dict:
    """
    Convert total seconds to hours, minutes, and seconds.
    
    Args:
        total_seconds (int): Total number of seconds.
        
    Returns:
        dict: Dictionary with 'hours', 'minutes', 'seconds' keys.
    """
    t = int(total_seconds)
    hours = t // 3600
    minutes = (t % 3600) // 60
    seconds = t % 60
    return {"hours": hours, "minutes": minutes, "seconds": seconds}


__all__ = [
    "exec_command",
    "run_commands",
    "check_connection",
    "convert_seconds",
]
