"""
Bootloader Download Module for Python Bootloader Application.

This module handles firmware file download, verification, decryption, and
preparation for flashing to the display hardware. It's the core of the
firmware update process.

Key Features:
    - Secure file download with token authentication
    - Encrypted file hash verification (SHA-256)
    - AWS KMS key decryption for file encryption key
    - AES-256-ECB file decryption
    - Original file hash verification after decryption
    - Final packet preparation with encryption support
    - Serial port communication for hash transmission

Process Flow:
    1. Download encrypted firmware from server
    2. Verify downloaded file hash
    3. Decrypt the file encryption key via KMS
    4. Decrypt firmware file with data key
    5. Verify decrypted file hash
    6. Format and encrypt final hash packet
    7. Send hash packet to display via serial
    8. Trigger firmware update via btl_host.py

Functions:
    download_and_flash: Main orchestrator (calls private helpers).
    _download_firmware: Download + header extraction + hash verification.
    _decrypt_firmware: KMS key decrypt + AES file decrypt + hash check.
    _prepare_packet: Strategy pattern packet creation + encryption.
    _send_and_trigger: Serial write + save firmware + trigger update.
"""

import os
import time
import json
import base64
import requests
import tempfile
import hashlib

from utils.crypto_utils import generate_hash, decrypt_file, decrypt_key_kms
from core.protocol.crc import calculate_crc16, calculate_little_endian
from core.protocol.packet_builder import format_hash_to_64_bytes, create_512byte_packet_v12
from utils.gpio_control import turn_BL_Detect_High, turn_BL_Detect_Low
from core.logGenerator import write_log
from core.app_state import AppState
from utils.decrypt_utils import encrypt_hex_block
from core.serial_port import SerialPort, SerialPortOpenError, SerialPortWriteError

from dotenv import load_dotenv
from utils.logger import logger
load_dotenv()


def sha256_hex_of_bytes(b: bytes) -> str:
    """
    Calculate SHA-256 hash of byte data.
    
    Args:
        b (bytes): Input data to hash.
        
    Returns:
        str: SHA-256 hash as 64-character lowercase hex string.
    """
    return hashlib.sha256(b).hexdigest()



def encrypt_final_packet(final_packet_bytes: bytes) -> bytes:
    """
    Encrypt the final packet (64-byte or 512-byte) using AES-256-CBC.
    
    This encryption is applied when the DU has encryption enabled,
    matching the encryption expected by the display hardware.
    
    Args:
        final_packet_bytes (bytes): Packet containing hash data (64 or 512 bytes).
        
    Returns:
        bytes: Encrypted packet (same size as input).
    """
    from utils.decrypt_utils import AES_KEY, AES_IV
    
    logger.info(f"=== ENCRYPTION DEBUG ===")
    logger.info(f"Packet size: {len(final_packet_bytes)} bytes")
    logger.info(f"Unencrypted packet (hex): {final_packet_bytes.hex()}")
    logger.info(f"AES Key (32 bytes): {AES_KEY.hex() if AES_KEY else 'NOT SET'}")
    logger.info(f"AES IV (16 bytes): {AES_IV.hex() if AES_IV else 'NOT SET'}")
    
    hex_str = final_packet_bytes.hex()
    encrypted_hex = encrypt_hex_block(hex_str)
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    
    logger.info(f"Encrypted packet (hex): {encrypted_bytes.hex()}")
    logger.info(f"========================")
    
    return encrypted_bytes


# ---------------------------------------------------------------------------
# Private helpers — extracted from the former monolithic download_and_flash
# ---------------------------------------------------------------------------

def _download_firmware(
    file_id: str,
    token: str,
    device_id: str,
    phoneNo: str,
    duNumber: str,
    displayNumber: str,
    callback_message,
    callback_error,
) -> dict | None:
    """
    Download firmware file from server and verify its integrity.

    Downloads the file, extracts required headers, and validates the
    encrypted file hash against the server-provided hash.

    Args:
        file_id: Server file ID to download.
        token: Bearer auth token.
        device_id: Device identifier for logging.
        phoneNo, duNumber, displayNumber: For error logging.
        callback_message: Status update callback.
        callback_error: Error callback.

    Returns:
        dict with keys {'file_bytes', 'original_hash', 'encrypted_key_hdr'}
        on success, or None on failure.
    """
    callback_message(f"Requesting file from server...")
    server_url = os.getenv("SERVER_URL")
    if not server_url:
        callback_error("SERVER_URL not set")
        return None

    download_url = f"{server_url}api/file/fileDownload/{file_id}"
    headers = {"Authorization": f"Bearer {token}"}

    resp = requests.get(download_url, headers=headers, timeout=30)
    if resp.status_code != 200:
        write_log(
            errorCode="E-21",
            errorName="File Download Failed",
            result="Fail",
            description=f"Failed to download file from server. Status code: {resp.status_code}",
            device_id=device_id,
            phoneNo=phoneNo,
            duNumber=duNumber,
            displayNumber=displayNumber,
            fileName=file_id,
        )
        callback_error(f"Failed to Download File")
        return None

    file_bytes = resp.content

    # Read headers (case-insensitive)
    original_hash = resp.headers.get("x-original-file-hash") or resp.headers.get("X-Original-File-Hash")
    encrypted_hash = resp.headers.get("x-encrypted-file-hash") or resp.headers.get("X-Encrypted-File-Hash")
    encrypted_key_hdr = resp.headers.get("x-encrypted-key") or resp.headers.get("X-Encrypted-Key")

    logger.info(f"original hash :  {original_hash}")
    logger.info(f"encrypted hash:  {encrypted_hash}")

    if not original_hash or not encrypted_hash or not encrypted_key_hdr:
        callback_error("Missing required headers from server")
        return None

    # Validate encrypted file hash
    callback_message("Checking file ....")
    calculated_encrypted_hash = sha256_hex_of_bytes(file_bytes)
    logger.info(f"Calculated encrypted hash: {calculated_encrypted_hash}")
    if calculated_encrypted_hash != encrypted_hash:
        write_log(
            errorCode="E-23",
            errorName="Encrypted File Hash Mismatch",
            result="Fail",
            description="Downloaded file hash does not match the expected encrypted hash from server",
            device_id=device_id,
            phoneNo=phoneNo,
            duNumber=duNumber,
            displayNumber=displayNumber,
            fileName=file_id,
        )
        callback_error("E23 - Encrypted File Mismatch")
        return None

    return {
        "file_bytes": file_bytes,
        "original_hash": original_hash,
        "encrypted_key_hdr": encrypted_key_hdr,
    }


def _decrypt_firmware(
    file_bytes: bytes,
    original_hash: str,
    encrypted_key_hdr: str,
    device_id: str,
    phoneNo: str,
    duNumber: str,
    displayNumber: str,
    file_id: str,
    callback_message,
    callback_error,
) -> dict | None:
    """
    Decrypt the firmware file using KMS-decrypted data key.

    Parses the encrypted key header, decrypts it via KMS, uses the
    resulting key to decrypt the firmware, and verifies the original hash.

    Args:
        file_bytes: Downloaded encrypted firmware bytes.
        original_hash: Expected hash of decrypted file.
        encrypted_key_hdr: JSON string containing base64-encoded encrypted key.
        device_id, phoneNo, duNumber, displayNumber, file_id: For logging.
        callback_message: Status update callback.
        callback_error: Error callback.

    Returns:
        dict with keys {'decrypted_bytes', 'original_hash'} on success,
        or None on failure.
    """
    callback_message("Please Wait...")

    # Parse encrypted key header
    try:
        parsed = json.loads(encrypted_key_hdr)
        if not isinstance(parsed, list) or len(parsed) == 0:
            callback_error("Invalid encrypted key header")
            return None
        buffer_key_b64 = parsed[0]
        buffer_key_bytes = base64.b64decode(buffer_key_b64)
    except Exception as e:
        callback_error(f"Failed to parse encrypted key header: {e}")
        return None

    # Decrypt data key via KMS
    callback_message("Checking file ....")
    decrypted_key = decrypt_key_kms(buffer_key_bytes)
    if not decrypted_key:
        callback_error("Failed to decrypt data key via KMS")
        return None

    if len(decrypted_key) not in (16, 24, 32):
        callback_message(f"Warning: decrypted key length = {len(decrypted_key)}")

    # Decrypt firmware file
    callback_message("Decrypting file with data key (AES-256-ECB)...")
    decrypted_bytes = decrypt_file(file_bytes.hex(), decrypted_key)
    if decrypted_bytes is False:
        callback_error("Failed to decrypt file content")
        return None

    # Verify original hash
    callback_message("Decrypted file. Verifying original hash...")
    calc_orig_hash = sha256_hex_of_bytes(decrypted_bytes)
    logger.info(f"Calculated original hash: {calc_orig_hash}")
    logger.info(f"Expected original hash: {original_hash}")
    if calc_orig_hash != original_hash:
        write_log(
            errorCode="E-24",
            errorName="Original File Hash Mismatch",
            result="Fail",
            description="Decrypted file hash does not match the expected original hash from server",
            device_id=device_id,
            phoneNo=phoneNo,
            duNumber=duNumber,
            displayNumber=displayNumber,
            fileName=file_id,
        )
        callback_error("E24 - Original file Mismatch")
        return None

    return {
        "decrypted_bytes": decrypted_bytes,
        "original_hash": original_hash,
    }


def _prepare_packet(
    original_hash: str,
    is_encryption_enable: bool,
    callback_message,
    callback_error,
) -> bytes | None:
    """
    Create and optionally encrypt the final hash packet.

    Uses the Strategy Pattern (via BootloaderVersionFactory) to select
    the appropriate packet format based on bootloader version.

    Args:
        original_hash: SHA-256 hash of the decrypted firmware.
        is_encryption_enable: Whether DU has encryption enabled.
        callback_message: Status update callback.
        callback_error: Error callback.

    Returns:
        bytes: Final packet (encrypted if required), or None on failure.
    """
    callback_message(" Please Wait...")

    state = AppState.get_instance()
    bootloader_version = state.bootloader_version_string
    logger.info(f"Bootloader version detected: {bootloader_version or 'Unknown'}")

    try:
        from core.bootloader_version_handler import BootloaderVersionFactory, BootloaderVersionContext

        strategy = BootloaderVersionFactory.get_strategy(bootloader_version)
        logger.info(f"Using {strategy.__class__.__name__} for v{strategy.version}")

        logger.info(f"Creating BootloaderVersionContext with hash={original_hash[:16]}..., phone={state.phone_number}")
        context = BootloaderVersionContext(
            file_hash=original_hash,
            phone_number=state.phone_number or "",
            employee_code="CZART000",
            username="TESTUSER"
        )
        logger.info(f"PacketContext created successfully")

        logger.info(f"Calling strategy.create_packet()...")
        callback_message(f"Creating {strategy.packet_size}-byte packet for bootloader v{strategy.version}...")

        final_packet = strategy.create_packet(context)

        if not isinstance(final_packet, bytes):
            callback_error(f"Strategy returned invalid packet type: {type(final_packet)}")
            return None

        logger.info(f"Created {len(final_packet)}-byte packet for v{strategy.version}")

        # Encrypt if strategy requires it
        if strategy.should_encrypt():
            callback_message(f"Encrypting {strategy.packet_size}-byte packet for v{strategy.version}...")
            try:
                final_packet = encrypt_final_packet(final_packet)
                if not isinstance(final_packet, bytes):
                    callback_error(f"Encryption returned invalid type: {type(final_packet)}")
                    return None
                logger.info(f"Successfully encrypted packet for v{strategy.version}")
            except Exception as e:
                callback_error(f"Failed to encrypt packet: {e}")
                return None
        else:
            logger.info(f"Packet will be sent UNENCRYPTED for v{strategy.version}")

    except ValueError as e:
        # Unknown version — fallback to legacy behavior
        callback_message("Bootloader version unknown - using encryption flag...")
        logger.warning(f"Unknown bootloader version: {bootloader_version}. Falling back to encryption flag. Error: {e}")

        final_packet = format_hash_to_64_bytes(original_hash)
        if final_packet is False:
            callback_error("Failed to format 64-byte packet")
            return None

        if is_encryption_enable:
            callback_message("Encrypting 64-byte packet (encryption flag enabled)...")
            try:
                final_packet = encrypt_final_packet(final_packet)
                logger.info("Encrypted 64-byte packet based on encryption flag")
            except Exception as e:
                callback_error(f"Failed to encrypt packet: {e}")
                return None
        else:
            logger.info("Sending UNENCRYPTED packet based on encryption flag")

    return final_packet


def _send_and_trigger(
    final_packet: bytes,
    decrypted_bytes: bytes,
    is_encryption_enable: bool,
    encryption_key: bytes,
    callback_message,
    callback_error,
    callback_firmware_update,
) -> bool:
    """
    Write packet to serial, save firmware to disk, and trigger update.

    Args:
        final_packet: Encrypted/unencrypted hash packet.
        decrypted_bytes: Decrypted firmware binary data.
        is_encryption_enable: Encryption flag for btl_host.
        encryption_key: 32-byte key for btl_host.
        callback_message: Status update callback.
        callback_error: Error callback.
        callback_firmware_update: Callback to start btl_host.py.

    Returns:
        bool: True on success, False on failure.
    """
    # Turn BL detect LOW before writing
    try:
        turn_BL_Detect_Low()
    except Exception as e:
        callback_message(f"Warning: BL detect low failed: {e}")

    # Wait 4 seconds (mirroring JS setTimeout 4000)
    time.sleep(4)

    # Write packet to serial
    callback_message("Opening serial port to write final packet...")
    try:
        with SerialPort(timeout=5) as ser:
            SerialPort.write_packet(ser, final_packet)
            callback_message("Final packet written to serial. Port closed.")
    except SerialPortOpenError as e:
        callback_error("Failed to Send Data to Display")
        return False
    except SerialPortWriteError as e:
        callback_error(f"Error during serial write: {e}")
        return False

    callback_message("Preparing firmware update...")

    # Wait 5 seconds before firmware update
    time.sleep(5)

    # Save decrypted file to temp location
    try:
        temp_dir = tempfile.gettempdir()
        output_path = os.path.join(temp_dir, "decrypted_firmware.bin")
        with open(output_path, "wb") as f:
            f.write(decrypted_bytes)
        logger.debug(f"Decrypted firmware saved to: {output_path}")
    except Exception as e:
        callback_error(f"Failed to save decrypted file: {e}")
        return False

    # Trigger firmware update
    encryption_key_hex = encryption_key.hex() if encryption_key else ""
    is_enc_flag = "1" if is_encryption_enable else "0"
    callback_firmware_update(output_path, encryption_key_hex, is_enc_flag)

    return True


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def download_and_flash(file_id: str,
                       token: str,
                       device_id: str,
                       is_encryption_enable: bool,
                       encryption_key: bytes,
                       phoneNo: str,
                       duNumber: str,
                       displayNumber: str,
                       callback_message,
                       callback_success,
                       callback_error,
                       callback_firmware_update):
    """
    Downloads firmware, verifies, decrypts, and writes final hash to serial.
    Runs synchronously — call from a thread.

    Data Flow:
      The encryption_key and is_encryption_enable params originate from
      AppState (set in du_reader._store_handshake_data), passed through
      the UI callback dict, then forwarded here by the UI layer.

    Process:
      1. Download firmware from server + verify encrypted hash
      2. Decrypt data key via KMS + decrypt firmware + verify original hash
      3. Create versioned hash packet + optional encryption
      4. Write packet to serial + save firmware + trigger btl_host
    """

    try:
        # Raise BL detect HIGH at start
        try:
            turn_BL_Detect_High()
        except Exception as e:
            callback_message(f"Warning: BL detect high failed: {e}")

        # 1. Download and verify firmware
        download_result = _download_firmware(
            file_id, token, device_id, phoneNo, duNumber, displayNumber,
            callback_message, callback_error,
        )
        if download_result is None:
            return False

        # 2. Decrypt firmware
        decrypt_result = _decrypt_firmware(
            download_result["file_bytes"],
            download_result["original_hash"],
            download_result["encrypted_key_hdr"],
            device_id, phoneNo, duNumber, displayNumber, file_id,
            callback_message, callback_error,
        )
        if decrypt_result is None:
            return False

        # 3. Prepare versioned hash packet
        final_packet = _prepare_packet(
            decrypt_result["original_hash"],
            is_encryption_enable,
            callback_message, callback_error,
        )
        if final_packet is None:
            return False

        # 4. Send packet and trigger firmware update
        return _send_and_trigger(
            final_packet,
            decrypt_result["decrypted_bytes"],
            is_encryption_enable, encryption_key,
            callback_message, callback_error, callback_firmware_update,
        )

    except Exception as e:
        import traceback
        error_tb = traceback.format_exc()
        logger.error(f"Unexpected error in download_and_flash: {e}")
        logger.error(f"Traceback:\n{error_tb}")
        callback_error(f"Unexpected error: {e}")
        try:
            turn_BL_Detect_Low()
        except:
            pass
        return False
