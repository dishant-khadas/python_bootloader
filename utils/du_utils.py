"""
Dispenser Unit (DU) Utilities — Backward Compatibility Shim.

This module re-exports functions that have been split into focused modules:
  - CRC:     core.protocol.crc
  - Crypto:  utils.crypto_utils
  - Packets: core.protocol.packet_builder
  - System:  utils.system_utils

New code should import from the specific modules directly.
This shim exists so that existing imports continue to work.
"""

# CRC functions — delegated to protocol layer (Phase 1)
from core.protocol.crc import calculate_crc16, calculate_little_endian, validate_crc

# Crypto functions — now in utils.crypto_utils
from utils.crypto_utils import generate_hash, decrypt_file, decrypt_key_kms

# Packet building — now in core.protocol.packet_builder
from core.protocol.packet_builder import format_hash_to_64_bytes, create_512byte_packet_v12

# System utilities — now in utils.system_utils
from utils.system_utils import exec_command, run_commands, check_connection, convert_seconds


def match_crc16(buffer_data: bytes) -> bool:
    """
    Validate CRC-16 in a 512-byte data buffer.
    
    .. deprecated:: Use core.protocol.crc.validate_crc() directly.
    """
    return validate_crc(buffer_data)


__all__ = [
    "calculate_crc16",
    "calculate_little_endian",
    "match_crc16",
    "generate_hash",
    "decrypt_file",
    "decrypt_key_kms",
    "format_hash_to_64_bytes",
    "create_512byte_packet_v12",
    "run_commands",
    "exec_command",
    "check_connection",
    "convert_seconds",
]
