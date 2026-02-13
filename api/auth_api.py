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
from core.logGenerator import write_log

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

    logger.debug(\"Initiating login API call\")
    logger.debug(f"URL: {API_URL}")
    logger.debug(f"Payload: {{phoneNo: '{phone}', password: [REDACTED]}}")

    try:
        res = requests.post(API_URL, json=payload, timeout=10)

        logger.debug(f"Status Code: {res.status_code}")
        logger.debug(f"Response length: {len(res.text)} chars")

        try:
            data = res.json()
            logger.debug("JSON parsed successfully")
        except Exception:
            logger.warning("JSON parse failed")


        if res.status_code == 200:
            data = res.json()
            if "token" in data:
                logger.info(f"Login successful for phone: {phone}")
                return True, data["token"], "success"

        # Log failed login attempt
        logger.warning(f"Login failed for phone: {phone}")
        write_log("E-51", "Login Failed", "Fail", "Invalid Credentials", device_id, phone, "", "", "")
        return False, "Invalid phone or password", "login_failed"

    except requests.exceptions.ConnectionError as e:
        logger.error(f"API connection error: {e}")
        return False, "No internet connection", "network_error"
    except requests.exceptions.Timeout as e:
        logger.error(f"API timeout: {e}")
        return False, "Connection timeout - please check your internet", "network_error"
    except Exception as e:
        logger.error(f"Unexpected API error: {e}", exc_info=True)
        return False, f"Network error: {str(e)}", "network_error"

