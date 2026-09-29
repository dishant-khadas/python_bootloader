"""
Bootloader Constants and Error Codes Module.

This module defines standardized error codes and their corresponding human-readable
descriptions used throughout the application for logging and UI display.
The error codes are dynamically loaded from error_codes.json.
"""
import json
import os
from utils.logger import logger

class ErrorCode:
    """Dynamically populated error codes from error_codes.json."""
    pass

ERROR_DESCRIPTIONS = {}

def _load_error_codes():
    """Load error codes from JSON and populate the ErrorCode class."""
    json_path = os.path.join(os.path.dirname(__file__), "error_codes.json")
    try:
        with open(json_path, "r") as f:
            error_data = json.load(f)
            
        for key, data in error_data.items():
            # Add to ErrorCode class as a static attribute
            setattr(ErrorCode, key, data["code"])
            # Map code (e.g., "L-10") to its name
            ERROR_DESCRIPTIONS[data["code"]] = data["name"]
    except Exception as e:
        logger.error(f"Failed to load error_codes.json: {e}")
        # Fallback values for critical errors if JSON loading fails
        ErrorCode.L_NETWORK_ERROR = "L-10"
        ERROR_DESCRIPTIONS["L-10"] = "Login Network Error"

# Execute loading at import time
_load_error_codes()

def get_error_name(code: str) -> str:
    """Get the human-readable name for an error code."""
    return ERROR_DESCRIPTIONS.get(code, "Unknown Error")
