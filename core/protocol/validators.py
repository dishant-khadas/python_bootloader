"""
Frame Validators for the Python Bootloader Application.

Provides validation functions for serial frame data including
SOP/EOP marker checks, DU/Display number format validation,
and encryption flag determination.

These validations were previously inline code in core/du_reader.py.

Usage:
    from core.protocol.validators import validate_sop_eop, validate_du_number

    if validate_sop_eop(frame_bytes):
        print("Frame markers are valid")
    
    if validate_du_number(99123456):
        print("DU number format is valid")
"""

from core.protocol.constants import (
    SOP_BYTE, EOP_BYTE, SOP_OFFSET, EOP_OFFSET,
    FRAME_SIZE, HARDWARE_TYPE_OFFSET, VALID_HARDWARE_TYPES, HARDWARE_TYPE_NAMES,
)


def validate_sop_eop(frame_bytes: bytes) -> bool:
    """
    Validate that a frame has correct SOP and EOP markers.
    
    Checks byte at SOP_OFFSET (0) equals 0x2A and byte at
    EOP_OFFSET (509) equals 0x3C.
    
    Args:
        frame_bytes (bytes): Frame data (at least 510 bytes).
        
    Returns:
        bool: True if both SOP and EOP markers are correct.
    """
    if len(frame_bytes) <= EOP_OFFSET:
        return False
    return (
        frame_bytes[SOP_OFFSET] == SOP_BYTE
        and frame_bytes[EOP_OFFSET] == EOP_BYTE
    )


def validate_du_number(du_number: int) -> bool:
    """
    Validate DU (Dispenser Unit) serial number format.
    
    A valid DU number must:
    - Be exactly 8 digits
    - Start with '99'
    
    Args:
        du_number (int): DU serial number to validate.
        
    Returns:
        bool: True if the DU number is valid.
    """
    du_str = str(du_number)
    return len(du_str) == 8 and du_str.startswith("99")


def validate_display_number(display_number: int) -> bool:
    """
    Validate Display serial number format.
    
    A valid Display number must:
    - Be exactly 8 digits
    - Start with '12'
    
    Args:
        display_number (int): Display serial number to validate.
        
    Returns:
        bool: True if the display number is valid.
    """
    display_str = str(display_number)
    return len(display_str) == 8 and display_str.startswith("12")


def get_encryption_flag(fw1: int, fw2: int) -> bool:
    """
    Determine if encryption is enabled based on firmware version.
    
    Encryption is enabled for firmware versions >= 11.8.
    
    Args:
        fw1 (int): Major firmware version number.
        fw2 (int): Minor firmware version number.
        
    Returns:
        bool: True if encryption should be enabled, False otherwise.
    """
    try:
        return fw1 >= 11 and fw2 >= 8
    except Exception:
        return False


def validate_hardware_type(frame_bytes: bytes, version_tuple: tuple[int, int]) -> int | None:
    """
    Extract and validate the hardware type from byte 427 of the handshake frame.

    Only applies to protocol version 1.2. For older versions, returns None
    (hardware type concept does not exist).

    Args:
        frame_bytes: Validated 512-byte handshake frame.
        version_tuple: Bootloader version as (major, minor), e.g. (1, 2).

    Returns:
        int: Hardware type value (0x01=display, 0x02=slave_display) for v1.2.
        None: For older protocol versions where this field is not defined.

    Raises:
        ValueError: If frame is too short or hardware type at byte 427 is invalid.
    """
    # Only applicable for v1.2
    if version_tuple != (1, 2):
        return None

    if len(frame_bytes) < FRAME_SIZE:
        raise ValueError(f"Frame too short: expected {FRAME_SIZE} bytes, got {len(frame_bytes)}")

    hw_type = frame_bytes[HARDWARE_TYPE_OFFSET]

    if hw_type not in VALID_HARDWARE_TYPES:
        raise ValueError(
            f"Invalid hardware type 0x{hw_type:02x} at byte {HARDWARE_TYPE_OFFSET}. "
            f"Expected 0x01 (display) or 0x02 (slave_display)"
        )

    return hw_type
