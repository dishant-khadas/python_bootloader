"""
CRC-16 Utilities for the Python Bootloader Application.

Provides CRC-16 calculation using the Modbus/IBM polynomial (0xA001),
little-endian conversion, and frame-level CRC validation.

These functions were originally in utils/du_utils.py and are now
centralized here as part of the protocol layer.

Usage:
    from core.protocol.crc import calculate_crc16, validate_crc

    # Calculate CRC for data
    crc = calculate_crc16(data_bytes)
    
    # Validate CRC in a complete frame
    is_valid = validate_crc(frame_bytes)
"""

from core.protocol.constants import CRC_DATA_END, CRC_START, CRC_END, FRAME_SIZE


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


def calculate_little_endian(crc: int) -> bytes:
    """
    Convert CRC to little-endian 2-byte bytes object.
    
    Args:
        crc (int): CRC-16 value to convert.
        
    Returns:
        bytes: 2-byte bytes object in little-endian format.
    """
    return crc.to_bytes(2, byteorder='little')


def validate_crc(
    buffer_data: bytes,
    data_end: int = CRC_DATA_END,
    crc_start: int = CRC_START,
    crc_end: int = CRC_END,
    min_length: int = FRAME_SIZE,
) -> bool:
    """
    Validate CRC-16 in a data buffer.
    
    Computes CRC over bytes [0:data_end] and compares with the CRC stored
    at bytes [crc_start:crc_end].
    
    Default parameters validate a standard 512-byte frame (CRC over [0:510],
    stored at [510:512]).
    
    Args:
        buffer_data (bytes): Buffer containing the data and CRC.
        data_end (int): End offset for CRC computation (exclusive).
        crc_start (int): Start offset of stored CRC.
        crc_end (int): End offset of stored CRC (exclusive).
        min_length (int): Minimum required buffer length.
        
    Returns:
        bool: True if computed CRC matches stored CRC, False otherwise.
    """
    if len(buffer_data) < min_length:
        return False
    crc = calculate_crc16(buffer_data[:data_end])
    computed = calculate_little_endian(crc)
    return computed == buffer_data[crc_start:crc_end]
