"""
Authentication API Module for Python Bootloader Application.

This module handles user authentication by communicating with the backend
authentication server. It provides login functionality for service engineers
using phone number and password credentials.

API Endpoint:
    POST /api/auth/serviceEngineer/phonelogin

Functions:
    login_api: Authenticate user with phone number and password.

Error Handling:
    - Network errors (no internet, timeout) return error_type="network_error"
    - Invalid credentials return error_type="login_failed"
    - Successful login returns error_type="success" with auth token
"""

import os
import requests
from logGenerator import write_log

# Authentication API endpoint
API_URL = "https://bootloader.czarmetricsystem.com/api/auth/serviceEngineer/phonelogin"


def login_api(phone: str, password: str) -> tuple[bool, str, str]:
    """
    Authenticate a service engineer with phone number and password.
    
    Makes a POST request to the authentication API with the provided
    credentials. Handles various error conditions including network
    issues and invalid credentials.
    
    Args:
        phone (str): The user's phone number (with or without country code).
        password (str): The user's password.
        
    Returns:
        tuple: A 3-tuple containing:
            - success (bool): True if login succeeded, False otherwise.
            - token_or_error (str): JWT token on success, error message on failure.
            - error_type (str): One of "success", "network_error", or "login_failed".
            
    Example:
        success, result, error_type = login_api("+919876543210", "password123")
        if success:
            token = result
        else:
            error_message = result
    """
    device_id = os.getenv("DEVICE_ID", "UNKNOWN")

    payload = {
        "phoneNo": phone,
        "password": password,
        "deviceID": '41999990'
    }

    print("\n---- LOGIN API CALL ----")
    print("URL:", API_URL)
    print("Payload:", payload)

    try:
        res = requests.post(API_URL, json=payload, timeout=10)

        print("Status Code:", res.status_code)
        print("Raw Response:", res.text)

        try:
            data = res.json()
            print("Parsed JSON:", data)
        except Exception:
            print("JSON Parse Failed")

        if res.status_code == 200:
            data = res.json()
            if "token" in data:
                print("Login Success! Token:", data["token"])
                return True, data["token"], "success"

        # Log failed login attempt
        print("Login Failed")
        write_log("E-51", "Login Failed", "Failed", "Invalid Credentials", device_id, phone, "", "", "")
        return False, "Invalid phone or password", "login_failed"

    except requests.exceptions.ConnectionError as e:
        print("API CONNECTION ERROR:", str(e))
        return False, "No internet connection", "network_error"
    except requests.exceptions.Timeout as e:
        print("API TIMEOUT ERROR:", str(e))
        return False, "Connection timeout - please check your internet", "network_error"
    except Exception as e:
        print("API ERROR:", str(e))
        return False, f"Network error: {str(e)}", "network_error"

