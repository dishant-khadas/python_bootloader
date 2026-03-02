"""
Dispenser Unit (DU) Reader Module for Python Bootloader Application.

This module handles the serial communication handshake with the display hardware
to read device identification data (DU number and Display number). It validates
the incoming data frame, extracts device info, and calls the DU_Update API.

Process Flow:
    1. Toggle BL_DETECT pin HIGH to signal readiness
    2. Read 512-byte data frame from serial port
    3. Validate frame (SOP/EOP, CRC) — decrypt if encrypted
    4. Extract and validate DU number and Display number
    5. Store handshake data in AppState
    6. Fetch DU update list from server API
    7. Return results via callback

Functions:
    read_du_from_serial: Main orchestrator (calls private helpers).
    _validate_frame_data: Frame validation + optional decryption.
    _extract_device_numbers: Parse + validate DU#/Display#.
    _store_handshake_data: Persist handshake results to AppState.
    _fetch_and_return: Call DU API and invoke success callback.
"""

import os
import time
import requests
from typing import Callable

from config import config
from utils.decrypt_utils import decrypt_hex_block
from utils.gpio_control import turn_BL_Detect_High, turn_BL_Detect_Low, turn_display_On, turn_display_Off, safe_cleanup
from core.logGenerator import write_log
from api.du_api import fetch_du_list
from core.display_logger import write_display_log
from core.app_state import AppState
from core.protocol.crc import calculate_crc16, calculate_little_endian, validate_crc
from core.protocol.constants import (
    REQUIRED_HEX_LENGTH, ENC_KEY_START, ENC_KEY_END,
    FW_V1_OFFSET, FW_V2_OFFSET,
)
from core.protocol.validators import validate_sop_eop, get_encryption_flag, validate_du_number, validate_display_number, validate_hardware_type
from core.protocol.frame_parser import parse_du_and_display
from core.serial_port import SerialPort, SerialPortOpenError, SerialPortTimeoutError, SerialPortError

from dotenv import load_dotenv
from utils.logger import logger
load_dotenv()

# Serial port configuration from centralized config
DEFAULT_SERIAL_PORT = config.SERIAL_PORT
DEFAULT_BAUDRATE = config.SERIAL_BAUD
HANDSHAKE_TIMEOUT = config.HANDSHAKE_TIMEOUT


# ---------------------------------------------------------------------------
# Private helpers — extracted from the former monolithic read_du_from_serial
# ---------------------------------------------------------------------------

def _validate_frame_data(
    buffer_bytes: bytes,
    first_block_hex: str,
    callback_ui_message,
    callback_ui_error,
    phoneNo: str,
) -> dict | None:
    """
    Validate the received 512-byte frame data.

    Handles three cases:
      1. Unencrypted: SOP/EOP match directly → CRC check
      2. Encrypted: SOP/EOP mismatch → decrypt → re-check SOP/EOP/CRC
      3. Partial mismatch: one marker matches, other doesn't → error

    Args:
        buffer_bytes: Raw 512-byte frame.
        first_block_hex: Hex string of the frame (for decryption).
        callback_ui_message: Status update callback.
        callback_ui_error: Error callback.
        phoneNo: For error logging.

    Returns:
        dict with keys {'buffer_bytes', 'is_encrypted', 'encryption_key',
        'firmware_v1', 'firmware_v2'} on success, or None on failure.
    """
    firmware_v1 = buffer_bytes[FW_V1_OFFSET]
    firmware_v2 = buffer_bytes[FW_V2_OFFSET]
    SOP = f"{buffer_bytes[0]:02x}"
    EOP = f"{buffer_bytes[509]:02x}"

    logger.debug(f"buffer len: {len(buffer_bytes)}")
    logger.info(f"SOP: {SOP}, EOP: {EOP}")

    # Case 1: Unencrypted frame
    if validate_sop_eop(buffer_bytes):
        logger.info("without encryption")
        callback_ui_message("SOP/EOP matched (unencrypted). Checking CRC...")

        if validate_crc(buffer_bytes):
            return {
                "buffer_bytes": buffer_bytes,
                "is_encrypted": get_encryption_flag(firmware_v1, firmware_v2),
                "encryption_key": None,
                "firmware_v1": firmware_v1,
                "firmware_v2": firmware_v2,
            }
        else:
            crc_calc = calculate_crc16(buffer_bytes[:510])
            crc_recv = buffer_bytes[510:512]
            callback_ui_message(f"CRC Mismatch: Calc {calculate_little_endian(crc_calc)} vs Recv {crc_recv}")
            safe_cleanup()
            write_log("E-42", "Invalid Data Received", "Fail", f"CRC Mismatch: Calculated {calculate_little_endian(crc_calc)} vs Received {crc_recv}", config.DEVICE_ID, phoneNo, "", "", "")
            callback_ui_error("E52 - Invalid Data Received")
            return None

    # Case 2: Encrypted frame (both markers mismatch)
    elif SOP != "2a" and EOP != "3c":
        logger.info("with encryption")
        callback_ui_message("Encrypted data detected (SOP/EOP mismatch)...")
        try:
            logger.debug(f"first_block_hex: {first_block_hex}")
            decrypted_hex = decrypt_hex_block(first_block_hex)
            logger.debug(f"decrypted_hex: {decrypted_hex}")
            buffer_bytes = bytes.fromhex(decrypted_hex)

            # Re-extract fields from decrypted data
            SOP = f"{buffer_bytes[0]:02x}"
            EOP = f"{buffer_bytes[509]:02x}"
            firmware_v1 = buffer_bytes[FW_V1_OFFSET]
            firmware_v2 = buffer_bytes[FW_V2_OFFSET]

            if validate_sop_eop(buffer_bytes):
                if validate_crc(buffer_bytes):
                    # Extract and decrypt encryption key
                    encrypted_key_bytes = buffer_bytes[ENC_KEY_START:ENC_KEY_END]
                    logger.debug(f"Extracted encrypted key: {len(encrypted_key_bytes)} bytes")

                    try:
                        decrypted_key_hex = decrypt_hex_block(encrypted_key_bytes.hex())
                        encryption_key = bytes.fromhex(decrypted_key_hex)
                        logger.debug(f"Decrypted encryption key: {len(encryption_key)} bytes")
                    except Exception as decrypt_err:
                        logger.warning(f"Warning: Failed to decrypt encryption key: {decrypt_err}")
                        encryption_key = encrypted_key_bytes

                    return {
                        "buffer_bytes": buffer_bytes,
                        "is_encrypted": True,
                        "encryption_key": encryption_key,
                        "firmware_v1": firmware_v1,
                        "firmware_v2": firmware_v2,
                    }
                else:
                    crc_calc = calculate_crc16(buffer_bytes[:510])
                    crc_recv = buffer_bytes[510:512]
                    write_log("E-42", "Invalid Data Received", "Fail", f"CRC fail after decrypt: Calculated {calculate_little_endian(crc_calc)} vs Received {crc_recv}", config.DEVICE_ID, phoneNo, "", "", "")
                    callback_ui_error("E52 - Invalid Data Received (CRC fail after decrypt)")
                    return None
            else:
                write_log("E-42", "Invalid Data Received", "Fail", f"SOP/EOP fail after decrypt: SOP={SOP}, EOP={EOP}", config.DEVICE_ID, phoneNo, "", "", "")
                callback_ui_error("E52 - Invalid Data Received (SOP/EOP fail after decrypt)")
                return None

        except Exception as e:
            safe_cleanup()
            write_log("E-42", "Invalid Data Received", "Fail", f"Decrypt failed: {e}", config.DEVICE_ID, phoneNo, "", "", "")
            callback_ui_error(f"E52 - Decrypt failed: {e}")
            return None

    # Case 3: Partial mismatch (one marker correct, other wrong)
    else:
        callback_ui_message(f"Invalid SOP/EOP combination: {SOP}/{EOP}")
        safe_cleanup()
        write_log("E-42", "Invalid Data Received", "Fail", f"SOP/EOP Mismatch: SOP={SOP}, EOP={EOP}", config.DEVICE_ID, phoneNo, "", "", "")
        callback_ui_error("E52 - Invalid Data Received (SOP/EOP Mismatch)")
        return None


def _extract_device_numbers(
    final_hex: str,
    callback_ui_error,
    phoneNo: str,
) -> tuple[int, int] | None:
    """
    Parse and validate DU and Display serial numbers from frame hex data.

    Args:
        final_hex: Validated frame as hex string.
        callback_ui_error: Error callback.
        phoneNo: For error logging.

    Returns:
        (du_number, display_number) tuple on success, None on failure.
    """
    try:
        du_number, display_number = parse_du_and_display(final_hex)
    except Exception as e:
        safe_cleanup()
        callback_ui_error(f"Parsing DU/Display failed: {e}")
        return None

    if not validate_du_number(du_number):
        safe_cleanup()
        write_log("E-58", "Invalid DU Number Received", "Fail", f"Invalid DU Number: {du_number} (must start with 99 and be 8 digits)", config.DEVICE_ID, phoneNo, str(du_number), "", "")
        callback_ui_error(f"E58 - Invalid DU Number Received: {du_number}")
        return None

    if not validate_display_number(display_number):
        safe_cleanup()
        write_log("E-58", "Invalid Display Number Received", "Fail", f"Invalid Display Number: {display_number} (must start with 12 and be 8 digits)", config.DEVICE_ID, phoneNo, str(du_number), str(display_number), "")
        callback_ui_error(f"E58 - Invalid Display Number Received: {display_number}")
        return None

    return du_number, display_number


def _store_handshake_data(
    buffer_bytes: bytes,
    du_number: int,
    display_number: int,
    is_encrypted: bool,
    encryption_key: bytes | None,
    final_hex: str,
    callback_ui_message,
) -> None:
    """
    Persist validated handshake data to AppState and write display log.

    Args:
        buffer_bytes: Validated 512-byte frame.
        du_number: Validated DU serial number.
        display_number: Validated Display serial number.
        is_encrypted: Whether encryption is enabled.
        encryption_key: Decrypted 32-byte key or None.
        final_hex: Frame hex string for display log.
        callback_ui_message: Status callback.
    """
    try:
        turn_BL_Detect_Low()
    except:
        pass

    callback_ui_message(f"DU detected: {du_number}, Display: {display_number}")

    # Store in AppState singleton
    try:
        state = AppState.get_instance()
        state.set_du_data(
            du_number=str(du_number),
            display_number=str(display_number),
            raw_bytes=buffer_bytes,
            is_encrypted=is_encrypted,
            encryption_key=encryption_key
        )
        logger.info(f"Stored DU data in AppState. Bootloader version: {state.bootloader_version_string}")
    except Exception as state_err:
        logger.error(f"Failed to store data in AppState: {state_err}")

    # Write display log to CSV
    try:
        write_display_log(final_hex)
    except Exception as log_err:
        logger.warning(f"Warning: Failed to write display log: {log_err}")


def _fetch_and_return(
    token: str,
    du_number: int,
    display_number: int,
    is_encrypted: bool,
    encryption_key: bytes | None,
    callback_ui_success,
    callback_ui_error,
) -> None:
    """
    Call DU_Update API and invoke the appropriate callback.

    Args:
        token: Auth token for API.
        du_number: Validated DU serial number.
        display_number: Validated Display serial number.
        is_encrypted: Encryption flag.
        encryption_key: Decrypted key or None.
        callback_ui_success: Success callback.
        callback_ui_error: Error callback.
    """
    success, options_or_msg, _ = fetch_du_list(token, du_number, display_number)
    logger.info(f"DU_Update API result: {success, options_or_msg}")

    if not success:
        if "No DU Assigned" in str(options_or_msg):
            callback_ui_error("No DU Assigned")
        else:
            callback_ui_error(f"DU_Update error: {options_or_msg}")
        turn_display_Off()
        return

    options = options_or_msg

    # Store du_options in AppState
    state = AppState.get_instance()
    state.du_options = options

    callback_ui_success({
        "duNumber": du_number,
        "displayNumber": display_number,
        "options": options,
        "isEncryptionEnable": is_encrypted,
        "encryptionKey": encryption_key,
        "hardwareType": state.hardware_type,
        "hardwareTypeName": state.hardware_type_name,
    })


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def read_du_from_serial(
    token: str,
    phoneNo: str,
    callback_ui_message: Callable[[str], None],
    callback_ui_success: Callable[[dict], None],
    callback_ui_error: Callable[[str], None],
    serial_port: str = DEFAULT_SERIAL_PORT,
    baudrate: int = DEFAULT_BAUDRATE,
):
    """
    Blocking function that does the DU handshake. Call it from a worker thread.

    Args:
      token: auth token (Bearer)
      phoneNo: user phone number for logging
      callback_ui_message: fn(str) for status updates
      callback_ui_success: fn(dict) on success (receives options from DU_Update API)
      callback_ui_error: fn(str) on error
      serial_port: device path (default from config)
      baudrate: int baud (default from config)

    Process:
      1. Toggle BL_DETECT HIGH → read serial data
      2. Validate frame (SOP/EOP/CRC, decrypt if needed)
      3. Extract and validate DU#/Display#
      4. Store handshake data in AppState
      5. Fetch DU update list from API → callback
    """

    try:
        # 1. Raise BL detect HIGH to signal readiness
        try:
            turn_BL_Detect_High()
            turn_display_On()
        except Exception as e:
            callback_ui_message(f"Warning: turn_BL_Detect_High failed: {e}")

        # 2. Read serial data
        callback_ui_message(f"Validation in Progress...")
        try:
            serial_port_obj = SerialPort(
                port=serial_port,
                baudrate=baudrate,
                timeout=0.5,
            )
            received_hex = serial_port_obj.read_hex_until(
                expected_length=REQUIRED_HEX_LENGTH,
                timeout_secs=HANDSHAKE_TIMEOUT,
                on_progress=lambda n: callback_ui_message(f"Received hex length: {n}"),
            )
            callback_ui_message(f"Data received (len: {len(received_hex)})")
        except SerialPortOpenError as e:
            callback_ui_error(f"E14 - Serial Port Error during Handshake: {e}")
            safe_cleanup()
            return
        except SerialPortTimeoutError as e:
            safe_cleanup()
            if "No data received" in str(e):
                callback_ui_error("E31 - No Data Received During Handshake")
                write_log("E-31", "No Data Received", "Fail", "No Data Received During Handshake", config.DEVICE_ID, phoneNo, "", "", "")
            else:
                callback_ui_error(f"E31 - Timeout: {e}")
            return
        except SerialPortError as e:
            safe_cleanup()
            callback_ui_error(f"E14 - Serial Port Error during Handshake: {e}")
            return

        # 3. Validate frame data (SOP/EOP, CRC, decrypt if needed)
        first_block_hex = received_hex[:REQUIRED_HEX_LENGTH]
        buffer_bytes = bytes.fromhex(first_block_hex)

        result = _validate_frame_data(buffer_bytes, first_block_hex, callback_ui_message, callback_ui_error, phoneNo)
        if result is None:
            return

        # 4. Extract and validate device numbers
        final_hex = result["buffer_bytes"].hex()
        devices = _extract_device_numbers(final_hex, callback_ui_error, phoneNo)
        if devices is None:
            return

        du_number, display_number = devices

        # 5. Store handshake data
        _store_handshake_data(
            result["buffer_bytes"], du_number, display_number,
            result["is_encrypted"], result["encryption_key"],
            final_hex, callback_ui_message,
        )

        # 5a. Validate hardware type (v1.2 only — byte 427)
        version_tuple = (result["firmware_v1"], result["firmware_v2"])
        try:
            hw_type = validate_hardware_type(result["buffer_bytes"], version_tuple)
            if hw_type is not None:
                callback_ui_message(f"Validating Hardware type")
        except ValueError as e:
            safe_cleanup()
            write_log("E-59", "Invalid Hardware Type", "Fail", str(e), config.DEVICE_ID, phoneNo, str(du_number), str(display_number), "")
            callback_ui_error(f"E59 - {e}")
            return

        # 6. Fetch DU list from API and return
        _fetch_and_return(
            token, du_number, display_number,
            result["is_encrypted"], result["encryption_key"],
            callback_ui_success, callback_ui_error,
        )

    except Exception as exc:
        safe_cleanup()
        callback_ui_error(f"Unexpected error: {exc}")
        return
