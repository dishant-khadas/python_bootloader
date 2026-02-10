"""
Dispenser Unit (DU) API Module for Python Bootloader Application.

This module provides API client functionality for fetching dispenser unit
information from the backend server. It retrieves the list of available
firmware files and configuration options for a specific DU and display.

API Endpoint:
    GET /api/dispenserUnit/DU_Update

Headers Required:
    - Authorization: Bearer token
    - deviceID: Device identifier
    - duNumber: Dispenser unit serial number
    - displayNumber: Display serial number

Functions:
    fetch_du_list: Fetch available firmware options for a DU.
"""

import os
import requests
from typing import Any

# Default server URL if not set in environment
DEFAULT_SERVER_URL = "https://bootloader.czarmetricsystem.com"


def fetch_du_list(token: str, du_number: int, display_number: int) -> tuple[bool, Any, bool]:
    """
    Fetch the list of available firmware files for a dispenser unit.
    
    Makes a GET request to the DU_Update API endpoint with the provided
    authentication token and device identifiers to retrieve available
    firmware options.
    
    Args:
        token (str): JWT authentication token from login.
        du_number (int): The dispenser unit serial number read from hardware.
        display_number (int): The display serial number read from hardware.
        
    Returns:
        tuple: A 3-tuple containing:
            - success (bool): True if the request succeeded and data was retrieved.
            - data_or_error (Any): On success, a dict with 'fileName' and 'fileId' lists.
                                   On failure, an error message string.
            - is_encryption (bool): Whether encryption is enabled for this DU.
            
    Example:
        success, data, is_encrypted = fetch_du_list(token, 12345678, 87654321)
        if success:
            file_names = data.get("fileName", [])
            file_ids = data.get("fileId", [])
    """
    base_url = os.getenv("SERVER_URL", DEFAULT_SERVER_URL)
    url = f"{base_url.rstrip('/')}/api/dispenserUnit/DU_Update"

    # Device ID from environment or fallback value
    device_id = os.getenv("DEVICE_ID", "41999990")

    headers = {
        "Authorization": f"Bearer {token}",
        "deviceID": device_id,
        "duNumber": str(du_number),
        "displayNumber": str(display_number)
    }

    print(f"\n---- FETCH DU LIST API ----")
    print(f"URL: {url}")
    print(f"Headers: {headers}")

    try:
        response = requests.get(url, headers=headers, timeout=15)
        print("Status Code:", response.status_code)
        print("Raw Response:", response.text)
        
        if response.status_code == 200:
            data = response.json()

            if "response" in data:
                # The 'response' key contains the firmware options
                options = data["response"]
                # Check for encryption flag in response
                is_enc = data.get("isEncryptionEnable", False)
                return True, options, is_enc
            else:
                return False, "Invalid Response Structure", False
        else:
            # Handle HTTP error responses
            print("Error Response:", response.text)
            try:
                err_data = response.json()
                msg = err_data.get("message", f"HTTP {response.status_code}")
            except:
                msg = f"HTTP Error {response.status_code}"
            return False, msg, False

    except Exception as e:
        print(f"Exception fetching DU list: {e}")
        return False, str(e), False

