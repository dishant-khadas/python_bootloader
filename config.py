"""
Centralized configuration for the Python Bootloader application.
All configurable values should be defined here to avoid hardcoding throughout the codebase.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration loaded from environment variables with sensible defaults."""
    
    # Server Configuration
    SERVER_URL = os.getenv("SERVER_URL", "http://192.168.1.171:3000/")
    API_URL = f"{SERVER_URL}api/logs/data-log"
    
    # Device Configuration
    DEVICE_ID = os.getenv("DEVICE_ID", "41999990")
    
    # Serial Configuration
    SERIAL_PORT = os.getenv("SERIAL_PORT", "/dev/ttyAMA0")
    SERIAL_BAUD = int(os.getenv("SERIAL_BAUD", "115200"))
    SERIAL_TIMEOUT = int(os.getenv("SERIAL_TIMEOUT", "15"))
    
    # GPIO Configuration
    GPIOCHIP = os.getenv("GPIOCHIP", "gpiochip0")
    BL_DETECT_PIN = int(os.getenv("BL_DETECT_PIN", "17"))
    DISPLAY_ON_PIN = int(os.getenv("DISPLAY_ON_PIN", "4"))
    
    # Handshake Configuration
    HANDSHAKE_TIMEOUT = int(os.getenv("HANDSHAKE_TIMEOUT", "10"))
    REQUIRED_HEX_LENGTH = 1024  # hex chars == 512 bytes
    
    # Encryption key location in the 512-byte data
    ENCRYPTED_KEY_START = 395
    ENCRYPTED_KEY_END = 427  # exclusive, so bytes[395:427] gives 32 bytes
    
    # Logging
    LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs.csv")


# Create a singleton instance for easy access
config = Config()
