"""
Frame Protocol Constants for the Python Bootloader Application.

Centralizes all magic numbers, byte offsets, and frame structure definitions
used across the 512-byte and 64-byte serial communication protocols.

These constants were previously scattered as magic numbers across:
    - core/du_reader.py
    - core/app_state.py
    - core/display_logger.py
    - utils/du_utils.py
    - config.py

Protocol Specification:
    512-byte frame layout:
    ┌──────┬────────────────┬──────┬──────────┬──────────┬─────────┬─────────┐
    │ SOP  │ Payload (data) │ ...  │ FW v1/v2 │ Enc Key  │   EOP   │  CRC16  │
    │ [0]  │ [1..392]       │      │ [393-394]│[395-426] │  [509]  │[510-511]│
    └──────┴────────────────┴──────┴──────────┴──────────┴─────────┴─────────┘
    
    64-byte frame layout (v1.0):
    ┌──────┬────────────────┬──────┬─────────┬──────────┐
    │ SOP  │  SHA-256 hash  │ pad  │   EOP   │  CRC16   │
    │ [0]  │ [1..32]        │      │  [61]   │ [62-63]  │
    └──────┴────────────────┴──────┴─────────┴──────────┘
"""

# ============================================================
# 512-byte Frame Constants
# ============================================================

# Frame markers
SOP_BYTE = 0x2A   # Start of Packet marker (asterisk '*')
EOP_BYTE = 0x3C   # End of Packet marker (less-than '<')

# Frame sizes
FRAME_SIZE = 512                    # Total frame size in bytes
REQUIRED_HEX_LENGTH = 1024          # FRAME_SIZE * 2 (hex chars for 512 bytes)

# Marker positions (byte offsets, 0-indexed)
SOP_OFFSET = 0                      # SOP at first byte
EOP_OFFSET = 509                    # EOP at byte 509

# CRC-16 positions
CRC_DATA_END = 510                  # CRC computed over bytes [0:510]
CRC_START = 510                     # CRC stored at bytes 510-511
CRC_END = 512                       # CRC end (exclusive) for slicing

# ============================================================
# Payload Field Offsets (within 512-byte frame)
# ============================================================

# DU and Display serial numbers (hex-digit positions in hex string)
DU_HEX_START = 2                    # Hex digit offset for DU number start
DU_HEX_END = 10                     # Hex digit offset for DU number end
DISPLAY_HEX_START = 10              # Hex digit offset for Display number start
DISPLAY_HEX_END = 18                # Hex digit offset for Display number end

# Firmware version (byte offsets in binary frame)
FW_V1_OFFSET = 393                  # Firmware major version byte
FW_V2_OFFSET = 394                  # Firmware minor version byte

# Encryption key (byte offsets in binary frame)
ENC_KEY_START = 395                 # Encryption key start byte
ENC_KEY_END = 427                   # Encryption key end byte (exclusive: [395:427] = 32 bytes)

# Hardware type identifier (v1.2 only, byte offset in binary frame)
HARDWARE_TYPE_OFFSET = 427          # Hardware identifier byte position
HARDWARE_TYPE_DISPLAY = 0x01        # Target hardware is a Display
HARDWARE_TYPE_SLAVE_DISPLAY = 0x02  # Target hardware is a Slave Display
VALID_HARDWARE_TYPES = {HARDWARE_TYPE_DISPLAY, HARDWARE_TYPE_SLAVE_DISPLAY}

HARDWARE_TYPE_NAMES = {
    HARDWARE_TYPE_DISPLAY: "display",
    HARDWARE_TYPE_SLAVE_DISPLAY: "slave_display",
}

# ============================================================
# 512-byte Response Packet Offsets (v1.2+ outgoing packet)
# ============================================================

# SHA-256 hash of firmware file
HASH_START = 1                      # Hash starts at byte 1
HASH_END = 33                       # Hash ends at byte 33 (exclusive: [1:33] = 32 bytes)

# Employee code (ASCII, 8 bytes)
EMPLOYEE_CODE_START = 33
EMPLOYEE_CODE_END = 41              # [33:41] = 8 bytes

# Username (ASCII, 25 bytes)
USERNAME_START = 41
USERNAME_END = 66                   # [41:66] = 25 bytes

# Phone number (ASCII, 16 bytes)
PHONE_START = 66
PHONE_END = 82                      # [66:82] = 16 bytes

# ============================================================
# 64-byte Frame Constants (v1.0 legacy)
# ============================================================

SMALL_FRAME_SIZE = 64               # Total frame size for v1.0
SMALL_SOP_OFFSET = 0                # SOP at first byte
SMALL_EOP_OFFSET = 61               # EOP at byte 61
SMALL_CRC_DATA_END = 62             # CRC computed over bytes [0:62]

# ============================================================
# Display Logger Nozzle Offsets
# ============================================================

# Nozzle data offsets within the hex string (for display_logger.py)
NOZZLE_OFFSETS = [87, 223, 359, 495]
NOZZLE_COUNT = 4

# Display logger field positions
DISPLAY_FIRMWARE_1_OFFSET = 19      # Hex position for firmware v1
DISPLAY_FIRMWARE_2_OFFSET = 21      # Hex position for firmware v2
AUTO_MODE_OFFSET = 638              # Hex position for auto mode
ONOFF_START = 640                   # Hex position for on/off start
ONOFF_END = 647                     # Hex position for on/off end
DISPLAY_SHA_START = 22              # Hex position for SHA start
DISPLAY_SHA_END = 85                # Hex position for SHA end
