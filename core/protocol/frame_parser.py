"""
Frame Parser for the Python Bootloader Application.

Parses raw 512-byte serial data into a structured FrameData dataclass.
Consolidates parsing logic that was previously scattered across:
    - core/du_reader.py (SOP/EOP extraction, firmware version, DU/Display parsing)
    - core/app_state.py (bootloader version extraction)
    - core/display_logger.py (DU/Display hex parsing)

Usage:
    from core.protocol.frame_parser import parse_frame, FrameData

    frame = parse_frame(raw_512_bytes)
    print(frame.du_number, frame.display_number)
    print(frame.fw_version)  # (11, 8)
    print(frame.crc_valid)   # True
"""

from dataclasses import dataclass
from typing import Optional

from core.protocol.constants import (
    SOP_OFFSET, EOP_OFFSET,
    FW_V1_OFFSET, FW_V2_OFFSET,
    ENC_KEY_START, ENC_KEY_END,
    DU_HEX_START, DU_HEX_END,
    DISPLAY_HEX_START, DISPLAY_HEX_END,
    FRAME_SIZE,
)
from core.protocol.crc import validate_crc
from core.protocol.validators import validate_sop_eop


@dataclass
class FrameData:
    """
    Structured representation of a parsed 512-byte serial frame.
    
    Attributes:
        raw_bytes: Full 512-byte frame data.
        sop: Start of Packet byte value.
        eop: End of Packet byte value.
        du_number: Dispenser Unit serial number (parsed from hex).
        display_number: Display serial number (parsed from hex).
        fw_version: Firmware version tuple (v1, v2).
        fw_version_string: Firmware version as string, e.g. "11.8".
        crc_valid: Whether the frame CRC check passed.
        is_sop_eop_valid: Whether SOP and EOP markers are correct.
        encryption_key_bytes: Raw 32-byte encryption key from frame (if present).
    """
    raw_bytes: bytes
    sop: int
    eop: int
    du_number: int
    display_number: int
    fw_version: tuple[int, int]
    fw_version_string: str
    crc_valid: bool
    is_sop_eop_valid: bool
    encryption_key_bytes: Optional[bytes] = None


def parse_du_and_display(hex_data: str) -> tuple[int, int]:
    """
    Extract DU number and Display number from hex string.
    
    Parses the hex-encoded 512-byte data to extract device serial numbers
    at the protocol-defined offsets.

    Args:
        hex_data (str): 1024-character hex string (512 bytes).

    Returns:
        tuple[int, int]: (du_number, display_number) as integers.
        
    Raises:
        ValueError: If hex_data is too short or contains invalid hex.
    """
    if len(hex_data) < DISPLAY_HEX_END:
        raise ValueError(
            f"Hex data too short: need at least {DISPLAY_HEX_END} chars, got {len(hex_data)}"
        )
    
    du_number = int(hex_data[DU_HEX_START:DU_HEX_END], 16)
    display_number = int(hex_data[DISPLAY_HEX_START:DISPLAY_HEX_END], 16)
    return du_number, display_number


def parse_frame(raw_bytes: bytes) -> FrameData:
    """
    Parse a raw 512-byte buffer into a structured FrameData.
    
    Extracts all protocol fields from the raw frame: SOP/EOP markers,
    CRC validity, firmware version, DU/Display numbers, and encryption key.
    
    Args:
        raw_bytes (bytes): Exactly 512 bytes of frame data.

    Returns:
        FrameData: Parsed frame with all fields populated.
        
    Raises:
        ValueError: If raw_bytes is not exactly 512 bytes.
    """
    if len(raw_bytes) != FRAME_SIZE:
        raise ValueError(f"Expected {FRAME_SIZE} bytes, got {len(raw_bytes)}")
    
    # Extract markers
    sop = raw_bytes[SOP_OFFSET]
    eop = raw_bytes[EOP_OFFSET]
    
    # Validate SOP/EOP
    is_sop_eop_valid = validate_sop_eop(raw_bytes)
    
    # Validate CRC
    crc_valid = validate_crc(raw_bytes)
    
    # Extract firmware version
    fw_v1 = raw_bytes[FW_V1_OFFSET]
    fw_v2 = raw_bytes[FW_V2_OFFSET]
    fw_version = (fw_v1, fw_v2)
    fw_version_string = f"{fw_v1}.{fw_v2}"
    
    # Parse DU and Display numbers from hex
    hex_data = raw_bytes.hex()
    du_number, display_number = parse_du_and_display(hex_data)
    
    # Extract encryption key bytes
    encryption_key_bytes = raw_bytes[ENC_KEY_START:ENC_KEY_END]
    
    return FrameData(
        raw_bytes=raw_bytes,
        sop=sop,
        eop=eop,
        du_number=du_number,
        display_number=display_number,
        fw_version=fw_version,
        fw_version_string=fw_version_string,
        crc_valid=crc_valid,
        is_sop_eop_valid=is_sop_eop_valid,
        encryption_key_bytes=encryption_key_bytes,
    )
