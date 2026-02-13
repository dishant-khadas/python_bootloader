"""
Dispenser Unit (DU) Utilities Module for Python Bootloader Application.

This module provides utility functions for firmware processing, CRC validation,
cryptographic operations, and network connectivity checks used during the
bootloader update process.

Key Functionality:
    - CRC-16 calculation and validation (Modbus polynomial)
    - SHA-256 hash generation for firmware integrity
    - AES-256-ECB decryption for encrypted firmware files
    - AWS KMS key decryption for secure key management
    - Network connectivity checks
    - WiFi connection management via nmcli

Cryptographic Notes:
    - CRC-16 uses polynomial 0xA001 (Modbus/IBM standard)
    - AES uses 256-bit keys in ECB mode for file decryption
    - KMS is used for decrypting data encryption keys

Functions:
    calculate_crc16: Calculate CRC-16 checksum.
    calculate_little_endian: Convert CRC to little-endian hex.
    match_crc16: Validate CRC in 512-byte buffer.
    generate_hash: Generate SHA-256 hash of hex data.
    decrypt_file: Decrypt firmware file using AES-256-ECB.
    decrypt_key_kms: Decrypt encryption key using AWS KMS.
    format_hash_to_64_bytes: Format hash for transmission.
    exec_command: Execute shell command.
    run_commands: Run WiFi connection commands.
    check_connection: Check internet connectivity.
    convert_seconds: Convert seconds to hours/minutes/seconds.
"""

import subprocess
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import boto3
import requests


def calculate_crc16(data: bytes) -> int:
    """
    Calculate CRC-16 checksum using Modbus/IBM polynomial.
    
    Uses polynomial 0xA001 which is the bit-reversed version of 0x8005
    (CRC-16-IBM). This matches the JavaScript implementation used in
    the original Node.js bootloader.
    
    Args:
        data (bytes): Input data to calculate CRC for.
        
    Returns:
        int: CRC-16 value (0x0000 to 0xFFFF).
    """
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if (crc & 1) != 0:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def calculate_little_endian(crc: int) -> str:
    """
    Convert CRC to little-endian 4-character hex string.
    
    Swaps the high and low bytes of the CRC value, matching the
    JavaScript implementation: ((crc >> 8) | ((crc & 0xFF) << 8))
    
    Args:
        crc (int): CRC-16 value to convert.
        
    Returns:
        str: 4-character lowercase hex string in little-endian format.
    """
    le = ((crc >> 8) | ((crc & 0xFF) << 8)) & 0xFFFF
    return format(le, "04x")


def match_crc16(buffer_data: bytes) -> bool:
    """
    Validate CRC-16 in a 512-byte data buffer.
    
    Computes CRC over bytes 0-509 and compares with the CRC stored
    in bytes 510-511. Used for validating data frames from hardware.
    
    Args:
        buffer_data (bytes): Buffer of at least 512 bytes.
        
    Returns:
        bool: True if computed CRC matches stored CRC, False otherwise.
    """
    if len(buffer_data) < 512:
        return False
    crc = calculate_crc16(buffer_data[:510])
    little_end = calculate_little_endian(crc)
    return little_end == buffer_data[510:512].hex()


def generate_hash(hex_data: str) -> str:
    """
    Generate SHA-256 hash of hex-encoded data.
    
    Args:
        hex_data (str): Hex string of data to hash.
        
    Returns:
        str: SHA-256 hash as 64-character hex string.
        
    Raises:
        ValueError: If hex_data is not valid hexadecimal.
    """
    try:
        file_bytes = bytes.fromhex(hex_data)
    except Exception as e:
        raise ValueError(f"generate_hash: invalid hex data: {e}")

    h = hashlib.sha256()
    h.update(file_bytes)
    return h.hexdigest()


def decrypt_file(hex_data: str, key: bytes) -> bytes:
    """
    Decrypt firmware file using AES-256-ECB.
    
    Args:
        hex_data (str): Hex string of encrypted file data.
        key (bytes): 32-byte AES key.
        
    Returns:
        bytes: Decrypted file content.
        
    Raises:
        ValueError: If key is not bytes or not 32 bytes long.
        
    Note:
        Attempts PKCS7 unpadding. If unpadding fails (custom padding
        or exact block alignment), returns raw decrypted data.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise ValueError("decrypt_file: key must be bytes")

    if len(key) != 32:
        raise ValueError("decrypt_file: key must be 32 bytes for AES-256")

    encrypted_bytes = bytes.fromhex(hex_data)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_bytes)

    # Attempt PKCS7 unpadding
    try:
        return unpad(decrypted, AES.block_size)
    except ValueError:
        # If padding is incorrect, return raw decrypted data
        return decrypted


def decrypt_key_kms(ciphertext: bytes, region: str = "ap-south-1") -> bytes | None:
    """
    Decrypt a data encryption key using AWS KMS.
    
    Uses the AWS KMS decrypt API to decrypt a ciphertext blob that
    was previously encrypted with a KMS customer master key.
    
    Args:
        ciphertext (bytes): Encrypted key ciphertext blob.
        region (str): AWS region for KMS. Default is "ap-south-1".
        
    Returns:
        bytes | None: Decrypted key bytes, or None on error.
    """
    try:
        client = boto3.client("kms", region_name=region)
        resp = client.decrypt(CiphertextBlob=ciphertext)
        return resp.get("Plaintext")
    except Exception as e:
        print("decrypt_key_kms error:", e)
        return None


def format_hash_to_64_bytes(hex_hash: str) -> bytes | bool:
    """
    Format a SHA-256 hash into a 64-byte transmission buffer.
    
    Creates a structured 64-byte buffer for sending the hash to hardware:
    - Byte 0: Start marker (0x2A)
    - Bytes 1-32: Hash bytes
    - Byte 61: End marker (0x3C)
    - Bytes 62-63: CRC-16 of bytes 0-61 (high byte, low byte)
    
    Args:
        hex_hash (str): 64-character hex string (32-byte SHA-256 hash).
        
    Returns:
        bytes: 64-byte formatted buffer.
        bool: False if formatting fails.
        
    Raises:
        ValueError: If hash is not exactly 64 hex characters.
    """
    try:
        if len(hex_hash) != 64:
            raise ValueError("Hash must be 64 hex characters (32 bytes)")

        hash_buf = bytes.fromhex(hex_hash)
        final = bytearray(64)

        # Set start marker
        final[0] = 0x2A
        # Copy hash bytes
        final[1:1+len(hash_buf)] = hash_buf
        # Set end marker
        final[61] = 0x3C

        # Calculate and append CRC-16
        crc = calculate_crc16(bytes(final[:62]))
        final[62] = (crc >> 8) & 0xFF  # High byte
        final[63] = crc & 0xFF         # Low byte

        return bytes(final)
    except Exception as e:
        print("format_hash_to_64_bytes error:", e)
        return False


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
        print("Running:", command if isinstance(command, str) else " ".join(command))
        
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
            print("Connection Success", ssid)
        return out
    except subprocess.CalledProcessError as e:
        stderr = e.stderr or ""
        if "No network" in stderr:
            print("Unable to find network")
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
        # Old vulnerable code: f"nmcli device wifi connect '{wifi_ssid}' password '{password}'"
        # This prevented attack like password = "'; rm -rf / #"
        out = exec_command(
            ["nmcli", "device", "wifi", "connect", wifi_ssid, "password", password],
            ssid=wifi_ssid,
            use_array=True  # Signal to exec_command to use array mode
        )
        return out
    except Exception as e:
        print("run_commands error:", e)
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
        print("No Internet Connection:", e)
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


# Expose module functions
__all__ = [
    "calculate_crc16",
    "calculate_little_endian",
    "match_crc16",
    "generate_hash",
    "decrypt_file",
    "decrypt_key_kms",
    "format_hash_to_64_bytes",
    "run_commands",
    "exec_command",
    "check_connection",
    "convert_seconds",
]
__all__ = [
    "calculate_crc16",
    "calculate_little_endian",
    "match_crc16",
    "generate_hash",
    "decrypt_file",
    "decrypt_key_kms",
    "format_hash_to_64_bytes",
    "run_commands",
    "exec_command",
    "check_connection",
    "convert_seconds",
]
