import os
import time
import json
import base64
import requests
import serial
import tempfile

from du_utils import (
    generate_hash,           # hex-string version (we will use bytes variant locally)
    decrypt_file,            # expects (hex_string, key_bytes) -> bytes
    decrypt_key_kms,         # KMS decrypt (ciphertext bytes) -> plaintext bytes
    format_hash_to_64_bytes, # hex-string -> 64-byte packet
)
from gpio_control import turn_BL_Detect_High, turn_BL_Detect_Low

import hashlib

from dotenv import load_dotenv
load_dotenv()

# --------- helper: sha256 of bytes (hex) ----------
def sha256_hex_of_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# --------- placeholder encrypt function (if you port Encrypt from JS) ----------
def encrypt_final_packet(final_packet_bytes: bytes) -> bytes:
    """
    Placeholder. If you implement the JS Encrypt() function in Python,
    replace this so it returns encrypted bytes (hex or raw bytes depending on expectation).
    For now, returns the same bytes (no encryption) — change when you have Encrypt.
    """
    # TODO: implement if required. For now: no-op
    return final_packet_bytes

# --------- main function ----------
def download_and_flash(file_id: str,
                       token: str,
                       device_id: str,
                       is_encryption_enable: bool,
                       callback_message,   # callback_message(text) to update UI/log
                       callback_success,   # callback_success() when done
                       callback_error):    # callback_error(error_text)
    """
    Downloads BIN by file_id, verifies, decrypts, and writes final hash to serial.
    Runs synchronously — call from a thread.
    """

    try:
        callback_message("Opening serial port...")
        # Raise BL detect HIGH at start (mimic Node behaviour where they set LOW earlier but here low is used after download)
        try:
            turn_BL_Detect_High()
        except Exception as e:
            callback_message(f"Warning: BL detect high failed: {e}")

        # 1) Download the file
        callback_message(f"Requesting file {file_id} from server...")
        server_url = os.getenv("SERVER_URL")
        if not server_url:
            callback_error("SERVER_URL not set")
            return False

        download_url = f"{server_url}api/file/fileDownload/{file_id}"
        headers = {"Authorization": f"Bearer {token}"}

        resp = requests.get(download_url, headers=headers, timeout=30)
        if resp.status_code != 200:
            callback_error(f"Failed to fetch file: HTTP {resp.status_code}")
            return False

        # response content is bytes
        file_bytes = resp.content

        # Read headers (case-insensitive)
        original_hash = resp.headers.get("x-original-file-hash") or resp.headers.get("X-Original-File-Hash")
        encrypted_hash = resp.headers.get("x-encrypted-file-hash") or resp.headers.get("X-Encrypted-File-Hash")
        encrypted_key_hdr = resp.headers.get("x-encrypted-key") or resp.headers.get("X-Encrypted-Key")

        callback_message(f"Received {len(file_bytes)} bytes. Validating headers...")

        if not original_hash or not encrypted_hash or not encrypted_key_hdr:
            callback_error("Missing required headers from server")
            return False

        # 2) Validate encrypted file hash
        callback_message("Checking encrypted file hash...")
        calculated_encrypted_hash = sha256_hex_of_bytes(file_bytes)
        if calculated_encrypted_hash != encrypted_hash:
            callback_error("E23 - Encrypted File Mismatch")
            return False

        callback_message("Encrypted file hash OK. Parsing encrypted key...")

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

        callback_message("Decrypting data key via KMS...")
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
        if calc_orig_hash != original_hash:
            callback_error("E24 - Original file Mismatch")
            return False

        callback_message("Original file hash matches. Preparing final packet...")

        # 4) Prepare final hash packet (formatHashTo64Bytes)
        final_packet = format_hash_to_64_bytes(calc_orig_hash)
        if final_packet is False:
            callback_error("Failed to format final packet")
            return False

        # If encryption is enabled for the DU, encrypt final packet before sending (placeholder)
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
        callback_message("Waiting 4 seconds before flashing...")
        time.sleep(4)

        # 7) Write final packet to serial port
        callback_message("Opening serial port to write final packet...")
        try:
            port_name = os.getenv("SERIAL_PORT", "/dev/ttyAMA0")
            ser = serial.Serial(port_name, baudrate=115200, timeout=5)
        except Exception as e:
            callback_error(f"Serial port open failed: {e}")
            return False

        try:
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

        callback_message("File flashed successfully.")
        callback_success({"status": "success", "duNumber": None, "displayNumber": None})
        return True

    except Exception as e:
        callback_error(f"Unexpected error: {e}")
        try:
            turn_BL_Detect_Low()
        except:
            pass
        return False
