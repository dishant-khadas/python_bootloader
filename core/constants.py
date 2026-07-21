"""
Bootloader Constants and Error Codes Module.

This module defines standardized error codes and their corresponding human-readable
descriptions used throughout the application for logging and UI display.
"""

class ErrorCode:
    # 1. Login & Authentication Phase (L-XX)
    L_NETWORK_ERROR = "L-10"
    L_INVALID_CREDENTIALS = "L-11"
    L_API_TIMEOUT = "L-12"
    L_MISSING_AUTH_DATA = "L-13"

    # 2. Handshake & DU Detection Phase (H-XX)
    H_SERIAL_OPEN_ERROR = "H-14"
    H_SERIAL_TIMEOUT = "H-31"
    H_NO_DU_ASSIGNED = "H-39"
    H_DU_UPDATE_API_ERROR = "H-40"
    H_INVALID_FRAME_FORMATTING = "H-42"
    H_CRC_VALIDATION_FAILED = "H-43"
    H_FRAME_DECRYPTION_FAILED = "H-52"
    H_INVALID_SERIAL_NUMBER = "H-58"
    H_INVALID_HARDWARE_TYPE = "H-59"

    # 3. Firmware Download & Prep Phase (D-XX)
    D_NO_FIRMWARE_AVAILABLE = "D-20"
    D_DOWNLOAD_API_FAILED = "D-21"
    D_MISSING_HEADERS = "D-22"
    D_ENCRYPTED_HASH_MISMATCH = "D-23"
    D_ORIGINAL_HASH_MISMATCH = "D-24"
    D_KMS_DECRYPTION_ERROR = "D-25"
    D_AES_DECRYPTION_ERROR = "D-26"
    D_SERIAL_WRITE_ERROR = "D-28"
    D_HASH_PACKET_TIMEOUT = "D-29"

    # 4. Firmware Programming Phase (P-XX)
    P_FIRMWARE_UPDATE_FAILED = "P-15"


ERROR_DESCRIPTIONS = {
    # L-XX
    ErrorCode.L_NETWORK_ERROR: "Login Network Error",
    ErrorCode.L_INVALID_CREDENTIALS: "Invalid Credentials",
    ErrorCode.L_API_TIMEOUT: "Login API Timeout",
    ErrorCode.L_MISSING_AUTH_DATA: "Missing Authentication Data",
    
    # H-XX
    ErrorCode.H_SERIAL_OPEN_ERROR: "Serial Port Open Error",
    ErrorCode.H_SERIAL_TIMEOUT: "Serial Read Timeout",
    ErrorCode.H_NO_DU_ASSIGNED: "No DU Assigned",
    ErrorCode.H_DU_UPDATE_API_ERROR: "DU_Update API Error",
    ErrorCode.H_INVALID_FRAME_FORMATTING: "Invalid Frame Formatting",
    ErrorCode.H_CRC_VALIDATION_FAILED: "CRC Validation Failed",
    ErrorCode.H_FRAME_DECRYPTION_FAILED: "Frame Decryption Failed",
    ErrorCode.H_INVALID_SERIAL_NUMBER: "Invalid Serial Number",
    ErrorCode.H_INVALID_HARDWARE_TYPE: "Invalid Hardware Type",
    
    # D-XX
    ErrorCode.D_NO_FIRMWARE_AVAILABLE: "No Firmware Available",
    ErrorCode.D_DOWNLOAD_API_FAILED: "Download API Failed",
    ErrorCode.D_MISSING_HEADERS: "Missing Headers",
    ErrorCode.D_ENCRYPTED_HASH_MISMATCH: "Encrypted Hash Mismatch",
    ErrorCode.D_ORIGINAL_HASH_MISMATCH: "Original Hash Mismatch",
    ErrorCode.D_KMS_DECRYPTION_ERROR: "KMS Decryption Error",
    ErrorCode.D_AES_DECRYPTION_ERROR: "AES File Decryption Error",
    ErrorCode.D_SERIAL_WRITE_ERROR: "Serial Write Error",
    ErrorCode.D_HASH_PACKET_TIMEOUT: "Hash Packet Timeout",
    
    # P-XX
    ErrorCode.P_FIRMWARE_UPDATE_FAILED: "Firmware Update Failed",
}

def get_error_name(code: str) -> str:
    """Get the human-readable name for an error code."""
    return ERROR_DESCRIPTIONS.get(code, "Unknown Error")
