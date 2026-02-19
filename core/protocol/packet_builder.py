"""
Protocol Packet Builder for Python Bootloader Application.

Constructs transmission packets in the protocol frame formats:
- 64-byte frame (bootloader v1.0/v1.1)
- 512-byte frame (bootloader v1.2+)

Previously part of the monolithic du_utils.py. Now lives in the protocol
layer alongside constants and CRC utilities it depends on.

Functions:
    format_hash_to_64_bytes: Build 64-byte hash transmission buffer.
    create_512byte_packet_v12: Build 512-byte packet for v1.2+ bootloaders.
"""

from core.protocol.constants import (
    FRAME_SIZE, SOP_BYTE, EOP_BYTE,
    SOP_OFFSET, EOP_OFFSET,
    CRC_DATA_END, CRC_START,
    SMALL_FRAME_SIZE, SMALL_SOP_OFFSET, SMALL_EOP_OFFSET, SMALL_CRC_DATA_END,
    HASH_START, HASH_END,
    EMPLOYEE_CODE_START, EMPLOYEE_CODE_END,
    USERNAME_START, USERNAME_END,
    PHONE_START, PHONE_END,
)
from core.protocol.crc import calculate_crc16, calculate_little_endian
from utils.logger import logger


def format_hash_to_64_bytes(hex_hash: str) -> bytes | bool:
    """
    Format a SHA-256 hash into a 64-byte transmission buffer.
    
    Creates a structured 64-byte buffer for sending the hash to hardware:
    - Byte 0: Start marker (SOP_BYTE)
    - Bytes 1-32: Hash bytes
    - Byte 61: End marker (EOP_BYTE)
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
        final = bytearray(SMALL_FRAME_SIZE)

        # Set start marker
        final[SMALL_SOP_OFFSET] = SOP_BYTE
        # Copy hash bytes
        final[1:1+len(hash_buf)] = hash_buf
        # Set end marker
        final[SMALL_EOP_OFFSET] = EOP_BYTE

        # Calculate and append CRC-16
        crc = calculate_crc16(bytes(final[:SMALL_CRC_DATA_END]))
        final[62] = (crc >> 8) & 0xFF  # High byte
        final[63] = crc & 0xFF         # Low byte

        logger.info(f"64 byte packet : {final}")

        return bytes(final)
    except Exception as e:
        logger.error(f"format_hash_to_64_bytes error: {e}")
        return False


def create_512byte_packet_v12(
    original_hash: str,
    employee_code: str = "CZART000",
    username: str = "TESTUSER",
    phone_number: str = ""
) -> bytes:
    """
    Create 512-byte packet for bootloader version 1.2+.
    
    Structure:
        Byte 0: SOP (SOP_BYTE)
        Bytes 1-32: 32-byte SHA-256 filehash (raw bytes)
        Bytes 33-40: 8-byte employee code (ASCII, padded with spaces)
        Bytes 41-65: 25-byte username (ASCII, padded with spaces)
        Bytes 66-81: 16-byte phone number (ASCII, padded with spaces)
        Bytes 82-509: Padding (0x00)
        Byte 509: EOP (EOP_BYTE)
        Bytes 510-511: CRC16 (little-endian)
    
    Args:
        original_hash (str): 64-character hex string of SHA-256 filehash.
        employee_code (str): Employee code, max 8 chars. Default "CZART000".
        username (str): Username, max 25 chars. Default "TESTUSER".
        phone_number (str): Phone number (e.g., "+91-7347530726").
        
    Returns:
        bytes: 512-byte packet ready for encryption.
    """
    packet = bytearray(FRAME_SIZE)
    
    # Byte 0: SOP
    packet[SOP_OFFSET] = SOP_BYTE
    
    # Bytes 1-32: Filehash (convert 64-char hex string to 32 bytes)
    filehash_bytes = bytes.fromhex(original_hash)
    if len(filehash_bytes) != 32:
        raise ValueError(f"Filehash must be 32 bytes, got {len(filehash_bytes)}")
    packet[HASH_START:HASH_END] = filehash_bytes
    
    # Bytes 33-40: Employee code (8 bytes, pad with ASCII spaces)
    emp_bytes = employee_code.encode('ascii')[:8].ljust(8, b' ')
    packet[EMPLOYEE_CODE_START:EMPLOYEE_CODE_END] = emp_bytes
    
    # Bytes 41-65: Username (25 bytes, pad with ASCII spaces)
    user_bytes = username.encode('ascii')[:25].ljust(25, b' ')
    packet[USERNAME_START:USERNAME_END] = user_bytes
    
    # Bytes 66-81: Phone number (16 bytes)
    # Convert "+91-7347530726" to bytes, then pad with null bytes
    phone_bytes = phone_number.encode('ascii')[:16].ljust(16, b' ')
    packet[PHONE_START:PHONE_END] = phone_bytes
    
    # Bytes 82-509: Already zeros (bytearray default initialization)
    
    # Byte 509: EOP
    packet[EOP_OFFSET] = EOP_BYTE
    
    # Bytes 510-511: CRC16 of bytes [0:510] in little-endian format
    crc = calculate_crc16(bytes(packet[:CRC_DATA_END]))
    crc_bytes = calculate_little_endian(crc)
    packet[CRC_START] = (crc >> 8) & 0xFF
    packet[CRC_START + 1] = crc & 0xFF

    logger.info(f"512 byte packet : {packet}")
    logger.info(f"Created 512-byte packet v1.2: hash={original_hash[:16]}..., emp={employee_code}, user={username}, phone={phone_number}")
    
    return bytes(packet)


__all__ = [
    "format_hash_to_64_bytes",
    "create_512byte_packet_v12",
]
