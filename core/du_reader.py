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
from core.exceptions import DecryptionError, DataValidationError, APIRequestError, BootloaderBaseError
from core.constants import ErrorCode, get_error_name

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

def _try_align_frame(
    raw_bytes: bytes,
    callback_ui_message,
) -> dict | None:
    """
    Attempt to realign a frame that may have leading noise bytes from power-on transients.
    Scans offsets 1 to 16 for valid unencrypted or encrypted 512-byte frames.

    Args:
        raw_bytes: Accumulated raw bytes (may be >512 bytes if noise was present).
        callback_ui_message: Status update callback.

    Returns:
        dict with validated frame data on success, or None if no valid frame found.
    """
    if len(raw_bytes) < 512:
        return None

    max_offset = min(16, len(raw_bytes) - 512)
    for offset in range(1, max_offset + 1):
        candidate = raw_bytes[offset:offset + 512]

        # 1. Check if candidate is a valid unencrypted frame
        if validate_sop_eop(candidate) and validate_crc(candidate):
            logger.warning(f"Recovered unencrypted frame at offset {offset} (discarded {offset} noise bytes)")
            callback_ui_message("Recovered frame alignment (unencrypted)...")
            fw_v1 = candidate[FW_V1_OFFSET]
            fw_v2 = candidate[FW_V2_OFFSET]
            return {
                "buffer_bytes": candidate,
                "is_encrypted": get_encryption_flag(fw_v1, fw_v2),
                "encryption_key": None,
                "firmware_v1": fw_v1,
                "firmware_v2": fw_v2,
            }

        # 2. Check if candidate is a valid encrypted frame
        try:
            decrypted_hex = decrypt_hex_block(candidate.hex())
            decrypted_buf = bytes.fromhex(decrypted_hex)
            if validate_sop_eop(decrypted_buf) and validate_crc(decrypted_buf):
                logger.warning(f"Recovered encrypted frame at offset {offset} (discarded {offset} noise bytes)")
                callback_ui_message("Recovered frame alignment (encrypted)...")
                fw_v1 = decrypted_buf[FW_V1_OFFSET]
                fw_v2 = decrypted_buf[FW_V2_OFFSET]
                encrypted_key_bytes = decrypted_buf[ENC_KEY_START:ENC_KEY_END]
                try:
                    dec_key_hex = decrypt_hex_block(encrypted_key_bytes.hex())
                    encryption_key = bytes.fromhex(dec_key_hex)
                except Exception:
                    encryption_key = encrypted_key_bytes
                return {
                    "buffer_bytes": decrypted_buf,
                    "is_encrypted": True,
                    "encryption_key": encryption_key,
                    "firmware_v1": fw_v1,
                    "firmware_v2": fw_v2,
                }
        except Exception:
            pass

    return None


def _validate_frame_data(
    buffer_bytes: bytes,
    first_block_hex: str,
    callback_ui_message,
    callback_ui_error,
    phoneNo: str = "",
) -> dict | None:
    """
    Validate the received 512-byte frame data.

    Handles three cases:
      1. Unencrypted: SOP/EOP match directly → CRC check
      2. Encrypted: SOP/EOP mismatch → decrypt → re-check SOP/EOP/CRC
      3. Partial mismatch: one marker matches, other doesn't → error
    If offset 0 fails, attempts alignment recovery to handle power-on noise bytes.

    Args:
        buffer_bytes: Raw frame bytes (at least 512 bytes).
        first_block_hex: Hex string of the frame (for decryption).
        callback_ui_message: Status update callback.
        callback_ui_error: Error callback.
        phoneNo: For error logging.

    Returns:
        dict with keys {'buffer_bytes', 'is_encrypted', 'encryption_key',
        'firmware_v1', 'firmware_v2'} on success, or None on failure.
    """
    frame_512 = buffer_bytes[:512]
    firmware_v1 = frame_512[FW_V1_OFFSET]
    firmware_v2 = frame_512[FW_V2_OFFSET]
    SOP = f"{frame_512[0]:02x}"
    EOP = f"{frame_512[509]:02x}"

    logger.debug(f"buffer len: {len(buffer_bytes)}")
    logger.info(f"SOP: {SOP}, EOP: {EOP}")

    phoneNo = phoneNo or AppState.get_instance().phone_number or ""

    # Case 1: Unencrypted frame at offset 0
    if validate_sop_eop(frame_512):
        logger.info("without encryption")
        callback_ui_message("SOP/EOP matched (unencrypted). Checking CRC...")

        if validate_crc(frame_512):
            return {
                "buffer_bytes": frame_512,
                "is_encrypted": get_encryption_flag(firmware_v1, firmware_v2),
                "encryption_key": None,
                "firmware_v1": firmware_v1,
                "firmware_v2": firmware_v2,
            }
        else:
            # Check if an alignment shift recovers CRC
            aligned = _try_align_frame(buffer_bytes, callback_ui_message)
            if aligned:
                return aligned

            crc_calc = calculate_crc16(frame_512[:510])
            crc_recv = frame_512[510:512]
            callback_ui_message(f"CRC Mismatch: Calc {calculate_little_endian(crc_calc)} vs Recv {crc_recv}")
            safe_cleanup()
            err_code = ErrorCode.H_CRC_VALIDATION_FAILED
            write_log(err_code, get_error_name(err_code), "Fail", f"CRC Mismatch: Calculated {calculate_little_endian(crc_calc)} vs Received {crc_recv}", config.DEVICE_ID, phoneNo, "", "", "")
            callback_ui_error(f"{err_code} - {get_error_name(err_code)}")
            return None

    # Case 2: Encrypted frame (both markers mismatch at offset 0)
    elif SOP != "2a" and EOP != "3c":
        logger.info("with encryption")
        callback_ui_message("Encrypted data detected (SOP/EOP mismatch)...")
        try:
            logger.debug(f"first_block_hex: {first_block_hex}")
            decrypted_hex = decrypt_hex_block(first_block_hex[:1024])
            logger.debug(f"decrypted_hex: {decrypted_hex}")
            decrypted_buffer = bytes.fromhex(decrypted_hex)

            # Re-extract fields from decrypted data
            dec_SOP = f"{decrypted_buffer[0]:02x}"
            dec_EOP = f"{decrypted_buffer[509]:02x}"
            dec_firmware_v1 = decrypted_buffer[FW_V1_OFFSET]
            dec_firmware_v2 = decrypted_buffer[FW_V2_OFFSET]

            if validate_sop_eop(decrypted_buffer):
                if validate_crc(decrypted_buffer):
                    # Extract and decrypt encryption key
                    encrypted_key_bytes = decrypted_buffer[ENC_KEY_START:ENC_KEY_END]
                    logger.debug(f"Extracted encrypted key: {len(encrypted_key_bytes)} bytes")

                    try:
                        decrypted_key_hex = decrypt_hex_block(encrypted_key_bytes.hex())
                        encryption_key = bytes.fromhex(decrypted_key_hex)
                        logger.debug(f"Decrypted encryption key: {len(encryption_key)} bytes")
                    except Exception as decrypt_err:
                        logger.warning(f"Warning: Failed to decrypt encryption key: {decrypt_err}")
                        encryption_key = encrypted_key_bytes

                    return {
                        "buffer_bytes": decrypted_buffer,
                        "is_encrypted": True,
                        "encryption_key": encryption_key,
                        "firmware_v1": dec_firmware_v1,
                        "firmware_v2": dec_firmware_v2,
                    }
                else:
                    # Check if alignment shift recovers a valid frame
                    aligned = _try_align_frame(buffer_bytes, callback_ui_message)
                    if aligned:
                        return aligned
                    crc_calc = calculate_crc16(decrypted_buffer[:510])
                    crc_recv = decrypted_buffer[510:512]
                    err_code = ErrorCode.H_CRC_VALIDATION_FAILED
                    write_log(err_code, get_error_name(err_code), "Fail", f"CRC fail after decrypt: Calculated {calculate_little_endian(crc_calc)} vs Received {crc_recv}", config.DEVICE_ID, phoneNo, "", "", "")
                    callback_ui_error(f"{err_code} - {get_error_name(err_code)}")
                    raise DataValidationError("CRC fail after decrypt")
            else:
                # Offset 0 decrypt failed SOP/EOP: Check if frame is shifted by leading noise
                aligned = _try_align_frame(buffer_bytes, callback_ui_message)
                if aligned:
                    return aligned
                err_code = ErrorCode.H_INVALID_FRAME_FORMATTING
                write_log(err_code, get_error_name(err_code), "Fail", f"SOP/EOP fail after decrypt: SOP={dec_SOP}, EOP={dec_EOP}", config.DEVICE_ID, phoneNo, "", "", "")
                callback_ui_error(f"{err_code} - {get_error_name(err_code)}")
                raise DataValidationError("SOP/EOP fail after decrypt")

        except Exception as e:
            if not isinstance(e, BootloaderBaseError):
                aligned = _try_align_frame(buffer_bytes, callback_ui_message)
                if aligned:
                    return aligned
            safe_cleanup()
            err_code = ErrorCode.H_FRAME_DECRYPTION_FAILED
            write_log(err_code, get_error_name(err_code), "Fail", f"Decrypt failed: {e}", config.DEVICE_ID, phoneNo, "", "", "")
            callback_ui_error(f"{err_code} - {get_error_name(err_code)}")
            raise DecryptionError(f"Decrypt failed: {e}")

    # Case 3: Partial mismatch (one marker correct, other wrong)
    else:
        aligned = _try_align_frame(buffer_bytes, callback_ui_message)
        if aligned:
            return aligned
        callback_ui_message(f"Invalid SOP/EOP combination: {SOP}/{EOP}")
        safe_cleanup()
        err_code = ErrorCode.H_INVALID_FRAME_FORMATTING
        write_log(err_code, get_error_name(err_code), "Fail", f"SOP/EOP Mismatch: SOP={SOP}, EOP={EOP}", config.DEVICE_ID, phoneNo, "", "", "")
        callback_ui_error(f"{err_code} - {get_error_name(err_code)}")
        raise DataValidationError(f"Invalid SOP/EOP combination: {SOP}/{EOP}")


def _extract_device_numbers(
    final_hex: str,
    callback_ui_error,
    phoneNo: str = "",
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
    phoneNo = phoneNo or AppState.get_instance().phone_number or ""
    try:
        du_number, display_number = parse_du_and_display(final_hex)
    except Exception as e:
        safe_cleanup()
        callback_ui_error(f"Parsing DU/Display failed: {e}")
        return None

    if not validate_du_number(du_number):
        safe_cleanup()
        err_code = ErrorCode.H_INVALID_SERIAL_NUMBER
        write_log(err_code, get_error_name(err_code), "Fail", f"Invalid DU Number: {du_number} (must start with 99 and be 8 digits)", config.DEVICE_ID, phoneNo, str(du_number), "", "")
        callback_ui_error(f"{err_code} - {get_error_name(err_code)}: DU {du_number}")
        return None

    if not validate_display_number(display_number):
        safe_cleanup()
        err_code = ErrorCode.H_INVALID_SERIAL_NUMBER
        write_log(err_code, get_error_name(err_code), "Fail", f"Invalid Display Number: {display_number} (must start with 12 and be 8 digits)", config.DEVICE_ID, phoneNo, str(du_number), str(display_number), "")
        callback_ui_error(f"{err_code} - {get_error_name(err_code)}: Display {display_number}")
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
    except Exception as e:
        logger.warning(f"Failed to set BL_Detect low: {e}")

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
    phoneNo: str = "",
    du_number: int = 0,
    display_number: int = 0,
    is_encrypted: bool = False,
    encryption_key: bytes | None = None,
    callback_ui_success = None,
    callback_ui_error = None,
) -> None:
    """
    Call DU_Update API and invoke the appropriate callback.

    Args:
        token: Auth token for API.
        phoneNo: User phone number for logging.
        du_number: Validated DU serial number.
        display_number: Validated Display serial number.
        is_encrypted: Encryption flag.
        encryption_key: Decrypted key or None.
        callback_ui_success: Success callback.
        callback_ui_error: Error callback.
    """
    phoneNo = phoneNo or AppState.get_instance().phone_number or ""
    success, options_or_msg, _ = fetch_du_list(token, du_number, display_number)
    logger.info(f"DU_Update API result: {success, options_or_msg}")

    if not success:
        if "No DU Assigned" in str(options_or_msg):
            err_code = ErrorCode.H_NO_DU_ASSIGNED
            callback_ui_error(f"{err_code} - {get_error_name(err_code)}")
            write_log(err_code, get_error_name(err_code), "Fail", "No DU Assigned", config.DEVICE_ID, phoneNo, "", "", "")
        else:
            err_code = ErrorCode.H_DU_UPDATE_API_ERROR
            callback_ui_error(f"{err_code} - {get_error_name(err_code)}: {options_or_msg}")
            write_log(err_code, get_error_name(err_code), "Fail", str(options_or_msg), config.DEVICE_ID, phoneNo, "", "", "")
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
    phoneNo: str = "",
    callback_ui_message: Callable[[str], None] = lambda _: None,
    callback_ui_success: Callable[[dict], None] = lambda _: None,
    callback_ui_error: Callable[[str], None] = lambda _: None,
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
        phoneNo = phoneNo or AppState.get_instance().phone_number or ""
        # 1. Trigger hardware handshake after serial port is opened and flushed
        def trigger_handshake():
            try:
                turn_BL_Detect_High()
                turn_display_On()
            except Exception as e:
                callback_ui_message(f"Warning: turn_BL_Detect_High failed: {e}")

        # 2. Read serial data with clean buffer and handshake trigger
        callback_ui_message("Validation in Progress...")
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
                pre_read_action=trigger_handshake,
            )
            callback_ui_message(f"Data received (len: {len(received_hex)})")
        except SerialPortOpenError as e:
            err_code = ErrorCode.H_SERIAL_OPEN_ERROR
            callback_ui_error(f"{err_code} - {get_error_name(err_code)}")
            safe_cleanup()
            return
        except SerialPortTimeoutError as e:
            safe_cleanup()
            err_code = ErrorCode.H_SERIAL_TIMEOUT
            if "No data received" in str(e):
                callback_ui_error(f"{err_code} - {get_error_name(err_code)}")
                write_log(err_code, get_error_name(err_code), "Fail", "No Data Received During Handshake", config.DEVICE_ID, phoneNo, "", "", "")
            else:
                callback_ui_error(f"{err_code} - {get_error_name(err_code)}: {e}")
            return
        except SerialPortError as e:
            safe_cleanup()
            err_code = ErrorCode.H_SERIAL_OPEN_ERROR
            callback_ui_error(f"{err_code} - {get_error_name(err_code)}: {e}")
            return

        # 3. Validate frame data (SOP/EOP, CRC, decrypt if needed, with noise recovery)
        first_block_hex = received_hex[:REQUIRED_HEX_LENGTH]
        buffer_bytes = bytes.fromhex(received_hex)

        try:
            result = _validate_frame_data(buffer_bytes, first_block_hex, callback_ui_message, callback_ui_error, phoneNo)
            if result is None:
                return
        except BootloaderBaseError:
            # Exception already logged/handled in helper
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
            err_code = ErrorCode.H_INVALID_HARDWARE_TYPE
            write_log(err_code, get_error_name(err_code), "Fail", str(e), config.DEVICE_ID, phoneNo, str(du_number), str(display_number), "")
            callback_ui_error(f"{err_code} - {get_error_name(err_code)}")
            return

        # 6. Fetch DU list from API and return
        _fetch_and_return(
            token, phoneNo, du_number, display_number,
            result["is_encrypted"], result["encryption_key"],
            callback_ui_success, callback_ui_error,
        )

    except Exception as exc:
        safe_cleanup()
        callback_ui_error(f"Unexpected error: {exc}")
        return
