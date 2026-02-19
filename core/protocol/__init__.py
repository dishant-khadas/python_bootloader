"""
Protocol package for the Python Bootloader Application.

Centralizes all frame protocol constants, CRC utilities, frame parsing,
and validation logic that was previously scattered across du_reader.py,
du_utils.py, app_state.py, and display_logger.py.

Usage:
    from core.protocol.constants import SOP_BYTE, EOP_BYTE, FRAME_SIZE
    from core.protocol.crc import calculate_crc16, validate_crc
    from core.protocol.frame_parser import FrameData, parse_frame
    from core.protocol.validators import validate_sop_eop, validate_du_number
"""

from core.protocol.constants import (
    SOP_BYTE, EOP_BYTE, FRAME_SIZE, REQUIRED_HEX_LENGTH,
    SOP_OFFSET, EOP_OFFSET, CRC_START, CRC_END, CRC_DATA_END,
    FW_V1_OFFSET, FW_V2_OFFSET,
    ENC_KEY_START, ENC_KEY_END,
    DU_HEX_START, DU_HEX_END,
    DISPLAY_HEX_START, DISPLAY_HEX_END,
    SMALL_FRAME_SIZE, SMALL_SOP_OFFSET, SMALL_EOP_OFFSET, SMALL_CRC_DATA_END,
    HASH_START, HASH_END,
    EMPLOYEE_CODE_START, EMPLOYEE_CODE_END,
    USERNAME_START, USERNAME_END,
    PHONE_START, PHONE_END,
)

from core.protocol.crc import (
    calculate_crc16,
    calculate_little_endian,
    validate_crc,
)

from core.protocol.frame_parser import (
    FrameData,
    parse_frame,
    parse_du_and_display,
)

from core.protocol.validators import (
    validate_sop_eop,
    validate_du_number,
    validate_display_number,
    get_encryption_flag,
)

from core.protocol.packet_builder import (
    format_hash_to_64_bytes,
    create_512byte_packet_v12,
)

__all__ = [
    # Constants
    "SOP_BYTE", "EOP_BYTE", "FRAME_SIZE", "REQUIRED_HEX_LENGTH",
    "SOP_OFFSET", "EOP_OFFSET", "CRC_START", "CRC_END", "CRC_DATA_END",
    "FW_V1_OFFSET", "FW_V2_OFFSET",
    "ENC_KEY_START", "ENC_KEY_END",
    "DU_HEX_START", "DU_HEX_END",
    "DISPLAY_HEX_START", "DISPLAY_HEX_END",
    "SMALL_FRAME_SIZE", "SMALL_SOP_OFFSET", "SMALL_EOP_OFFSET", "SMALL_CRC_DATA_END",
    "HASH_START", "HASH_END",
    "EMPLOYEE_CODE_START", "EMPLOYEE_CODE_END",
    "USERNAME_START", "USERNAME_END",
    "PHONE_START", "PHONE_END",
    # CRC
    "calculate_crc16", "calculate_little_endian", "validate_crc",
    # Frame Parser
    "FrameData", "parse_frame", "parse_du_and_display",
    # Validators
    "validate_sop_eop", "validate_du_number", "validate_display_number",
    "get_encryption_flag",
    # Packet Builder
    "format_hash_to_64_bytes", "create_512byte_packet_v12",
]
