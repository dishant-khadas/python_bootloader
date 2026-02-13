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
    download_and_flash: Main firmware download and verification function.
    sha256_hex_of_bytes: Calculate SHA-256 hash of bytes.
    encrypt_final_packet: Encrypt the 64-byte hash packet.
"""

import os
import time
import json
import base64
import requests
import serial
import tempfile
import hashlib

from utils.du_utils import (
    generate_hash,           # hex-string version (we will use bytes variant locally)
    decrypt_file,            # expects (hex_string, key_bytes) -> bytes
    decrypt_key_kms,         # KMS decrypt (ciphertext bytes) -> plaintext bytes
    format_hash_to_64_bytes, # hex-string -> 64-byte packet
)
from utils.gpio_control import turn_BL_Detect_High, turn_BL_Detect_Low
from core.logGenerator import write_log
from utils.decrypt_utils import encrypt_hex_block

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
    Encrypt the 64-byte final packet using AES-256-CBC.
    
    This encryption is applied when the DU has encryption enabled,
    matching the encryption expected by the display hardware.
    
    Args:
        final_packet_bytes (bytes): 64-byte packet containing hash data.
        
    Returns:
        bytes: Encrypted 64-byte packet.
    """
    hex_str = final_packet_bytes.hex()
    encrypted_hex = encrypt_hex_block(hex_str)
    return bytes.fromhex(encrypted_hex)



# --------- main function ----------
def download_and_flash(file_id: str,
                       token: str,
                       device_id: str,
                       is_encryption_enable: bool,
                       encryption_key: bytes,  # 32-byte key from decrypted 512-byte data
                       phoneNo: str,           # phone number from login
                       duNumber: str,          # DU serial number from 512 bytes
                       displayNumber: str,     # Display serial number from 512 bytes
                       callback_message,   # callback_message(text) to update UI/log
                       callback_success,   # callback_success(result_dict) when done
                       callback_error,     # callback_error(error_text)
                       callback_firmware_update):  # callback_firmware_update(decrypted_file_path, encryption_key_hex, is_enc_flag)
    """
    Downloads BIN by file_id, verifies, decrypts, and writes final hash to serial.
    Runs synchronously — call from a thread.
    """

    try:
        # Raise BL detect HIGH at start (mimic Node behaviour where they set LOW earlier but here low is used after download)
        try:
            turn_BL_Detect_High()
        except Exception as e:
            callback_message(f"Warning: BL detect high failed: {e}")

        # 1) Download the file
        callback_message(f"Requesting file from server...")
        server_url = os.getenv("SERVER_URL")
        if not server_url:
            callback_error("SERVER_URL not set")
            return False

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
            return False

        # response content is bytes
        file_bytes = resp.content

        # Read headers (case-insensitive)
        original_hash = resp.headers.get("x-original-file-hash") or resp.headers.get("X-Original-File-Hash")
        encrypted_hash = resp.headers.get("x-encrypted-file-hash") or resp.headers.get("X-Encrypted-File-Hash")
        encrypted_key_hdr = resp.headers.get("x-encrypted-key") or resp.headers.get("X-Encrypted-Key")

        logger.info(f"original hash :  {original_hash}")
        logger.info(f"encrypted hash:  {encrypted_hash}")

        if not original_hash or not encrypted_hash or not encrypted_key_hdr:
            callback_error("Missing required headers from server")
            return False

        # 2) Validate encrypted file hash
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
            return False

        callback_message("Please Wait...")

        # 3) Parse encrypted key (expected to be JSON array string whose first element is base64)
        try:
            parsed = json.loads(encrypted_key_hdr)
            if not isinstance(parsed, list) or len(parsed) == 0:
                callback_error("Invalid encrypted key header")
                return False
            buffer_key_b64 = parsed[0]
            buffer_key_bytes = base64.b64decode(buffer_key_b64)
        except Exception as e:
            callback_error(f"Failed to parse encrypted key header: {e}")
            return False

        callback_message("Checking file ....")
        decrypted_key = decrypt_key_kms(buffer_key_bytes)
        if not decrypted_key:
            callback_error("Failed to decrypt data key via KMS")
            return False

        # decrypted_key likely bytes (Uint8Array equivalent). Ensure length 32
        if len(decrypted_key) not in (16, 24, 32):
            # Expect 32 for AES-256; if AWS returns different, still allow but warn
            callback_message(f"Warning: decrypted key length = {len(decrypted_key)}")

        callback_message("Decrypting file with data key (AES-256-ECB)...")
        # decrypt_file expects hex string as first arg, so convert bytes to hex
        decrypted_bytes = decrypt_file(file_bytes.hex(), decrypted_key)
        if decrypted_bytes is False:
            callback_error("Failed to decrypt file content")
            return False

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
            return False

        callback_message(" Please Wait...")

        # 4) Prepare final hash packet (formatHashTo64Bytes)
        final_packet = format_hash_to_64_bytes(original_hash)
        logger.debug(f"Final packet (hex) dishant1:  {final_packet}")
        logger.debug(f"Final packet (hex) dishant2:  {final_packet.hex()}")
        if final_packet is False:
            callback_error("Failed to format final packet")
            return False

        # If encryption is enabled for the DU, encrypt final packet before sending (placeholder)
        logger.info(f"is enc enabled :  {is_encryption_enable}")
        if is_encryption_enable:
            callback_message("Encrypting final packet...")
            try:
                final_packet = encrypt_final_packet(final_packet)
            except Exception as e:
                callback_error(f"Failed to encrypt final packet: {e}")
                return False

        # 5) Turn BL detect LOW before writing (as in node code)
        try:
            turn_BL_Detect_Low()
        except Exception as e:
            callback_message(f"Warning: BL detect low failed: {e}")

        # 6) Wait 4 seconds (node had a setTimeout 4000)
        time.sleep(4)

        # 7) Write final packet to serial port
        callback_message("Opening serial port to write final packet...")
        try:
            port_name = os.getenv("SERIAL_PORT", "/dev/ttyAMA0")
            ser = serial.Serial(port_name, baudrate=115200, timeout=5)
        except Exception as e:
            # callback_error(f"Serial port open failed: {e}")
            callback_error("Failed to Send Data to Display")

            return False

        try:
            logger.info("Writing final packet to serial...")
            logger.debug(f"Final packet (hex) :  {final_packet.hex()}")
            ser.write(final_packet)
            ser.flush()
            callback_message("Final packet written to serial. Closing port...")
        except Exception as e:
            callback_error(f"Error during serial write: {e}")
            ser.close()
            return False
        finally:
            try:
                ser.close()
            except:
                pass

        callback_message("Preparing firmware update...")
        
        # 8) Wait 5 seconds before starting firmware update (as per JS implementation)
        time.sleep(5)
        
        # 9) Save decrypted file to temp location for btl_host.py
        try:
            temp_dir = tempfile.gettempdir()
            output_path = os.path.join(temp_dir, "decrypted_firmware.bin")
            with open(output_path, "wb") as f:
                f.write(decrypted_bytes)
            logger.debug(f"Decrypted firmware saved to: {output_path}")
        except Exception as e:
            callback_error(f"Failed to save decrypted file: {e}")
            return False
        
        # 10) Prepare encryption key hex string for btl_host.py
        encryption_key_hex = encryption_key.hex() if encryption_key else ""
        is_enc_flag = "1" if is_encryption_enable else "0"
        
        # 11) Trigger firmware update callback to start btl_host.py
        callback_firmware_update(output_path, encryption_key_hex, is_enc_flag)
        
        return True

    except Exception as e:
        callback_error(f"Unexpected error: {e}")
        try:
            turn_BL_Detect_Low()
        except:
            pass
        return False
