"""
Centralized configuration for the Python Bootloader application.
All configurable values should be defined here to avoid hardcoding throughout the codebase.
"""

import os
import sys
from dotenv import load_dotenv

# Load .env from the correct location (handle PyInstaller bundle)
if getattr(sys, 'frozen', False):
    # Running as PyInstaller bundle - .env is in _MEIPASS
    base_path = sys._MEIPASS
else:
    # Running as normal Python script
    base_path = os.path.dirname(os.path.abspath(__file__))

env_path = os.path.join(base_path, '.env')
load_dotenv(env_path)


class Config:
    """Application configuration loaded from environment variables with sensible defaults."""
    
    # Server Configuration
    SERVER_URL = os.getenv("SERVER_URL")
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
    
    # Encryption Keys (SECURITY: Load from environment, not hardcoded)
    # These are AES-256-CBC encryption keys used for firmware decryption
    AES_KEY_HEX = os.getenv("AES_KEY_HEX")
    AES_IV_HEX = os.getenv("AES_IV_HEX")
    
    # Parse hex keys to bytes (only if provided in environment)
    AES_KEY: bytes | None = None
    AES_IV: bytes | None = None
    
    if AES_KEY_HEX and AES_IV_HEX:
        try:
            AES_KEY = bytes.fromhex(AES_KEY_HEX)
            AES_IV = bytes.fromhex(AES_IV_HEX)
            
            # Validate key sizes
            if len(AES_KEY) != 32:  # 256-bit key
                raise ValueError(f"AES_KEY must be 32 bytes (256 bits), got {len(AES_KEY)} bytes")
            if len(AES_IV) != 16:   # 128-bit IV
                raise ValueError(f"AES_IV must be 16 bytes (128 bits), got {len(AES_IV)} bytes")
                
            print(f"✓ Encryption keys loaded from environment (Key: {len(AES_KEY)} bytes, IV: {len(AES_IV)} bytes)")
        except ValueError as e:
            raise ValueError(f"Invalid encryption key format in environment: {e}")
    else:
        # No encryption keys in environment — encryption features will be unavailable
        # SECURITY: Hardcoded keys (legacy encKey.py) have been removed.
        # For production, set AES_KEY_HEX and AES_IV_HEX in your .env file.
        print("ℹ️  No encryption keys configured. Set AES_KEY_HEX and AES_IV_HEX in .env")


# Create a singleton instance for easy access
config = Config()
