# du_reader.py
import os
import time
import requests
import serial
from typing import Callable

from decrypt_utils import decrypt_hex_block
from du_utils import calculate_crc16, calculate_little_endian
from gpio_control import turn_BL_Detect_High, turn_BL_Detect_Low

from dotenv import load_dotenv
load_dotenv()

# Configurable defaults
DEFAULT_SERIAL_PORT = os.getenv("SERIAL_PORT", "/dev/ttyS3")
DEFAULT_BAUDRATE = int(os.getenv("SERIAL_BAUD", "115200"))
HANDSHAKE_TIMEOUT = 10  # seconds
REQUIRED_HEX_LENGTH = 1024  # hex chars == 512 bytes


def get_encryption_flag(fw1: int, fw2: int) -> bool:
    """
    Port of getEncryptionFlag (simple heuristic: firmware >= some version).
    Adjust logic if you have a different rule.
    """
    try:
        return (fw1 >= 11 and fw2 >= 8)
    except Exception:
        return False


def parse_du_and_display_from_hex(first_block_hex: str):
    """
    first_block_hex: first 1024 hex chars (string) like JS receivedData.slice(0,1024)
    JS used duStartIndex = 2, displayStartIndex = 10 (these are indices into the hex string).
    This returns integers same as Node's Number("0x" + slice).
    """
    du_start = 2
    display_start = 10
    display_end = 18

    # slice returns hex substrings — interpret as big-endian hex numbers like JS
    du_hex = first_block_hex[du_start:display_start]      # 8 hex chars -> 4 bytes
    display_hex = first_block_hex[display_start:display_end]  # next 8 hex chars

    du_number = int(du_hex, 16)
    display_number = int(display_hex, 16)
    return du_number, display_number


def parse_du_and_display_from_hex(hex_str: str):
    """
    EXACT JS BEHAVIOR:
    duNumber     = Number("0x" + receivedData.slice(2, 10))
    displayNumber= Number("0x" + receivedData.slice(10,18))
    """
    du_hex = hex_str[2:10]          # hex characters, not bytes
    display_hex = hex_str[10:18]

    return int(du_hex, 16), int(display_hex, 16)



def read_du_from_serial(
    token: str,
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
      callback_ui_message: fn(str) for status updates
      callback_ui_success: fn(dict) on success (receives options from DU_Update API)
      callback_ui_error: fn(str) on error
      serial_port: device path (default '/dev/ttyS3')
      baudrate: int baud

    Behavior mirrors your JS:
      - toggle BL_DETECT HIGH
      - open serial
      - accumulate hex chunks until >= 1024 chars (512 bytes)
      - build buffer, check SOP/EOP; if mismatch -> decrypt_hex_block(receivedHex)
      - check CRC using calculate_crc16() and calculate_little_endian()
      - determine isEncryptionEnable via firmware bytes
      - call DU_Update API with headers Authorization Bearer, deviceID, duNumber, displayNumber
      - callback_ui_success(options) on success
      - ensures turn_BL_Detect_Low() in error/final branches
    """

    try:
        # raise BL detect high (start handshake)
        try:
            turn_BL_Detect_High()
        except Exception as e:
            callback_ui_message(f"Warning: turn_BL_Detect_High failed: {e}")

        callback_ui_message(f"Opening serial port {serial_port}...")
        try:
            ser = serial.Serial(serial_port, baudrate=baudrate, timeout=0.5)
        except Exception as e:
            callback_ui_error(f"E14 - Serial Port Error during Handshake: {e}")
            try:
                turn_BL_Detect_Low()
            except:
                pass
            return

        received_hex = ""
        start_time = time.time()
        is_encryption_enable = False
        buffer_bytes = b""

        callback_ui_message("Waiting for DU...")

        while True:
            # timeout if nothing arrives for HANDSHAKE_TIMEOUT seconds
            if time.time() - start_time > HANDSHAKE_TIMEOUT and len(received_hex) == 0:
                try:
                    turn_BL_Detect_Low()
                except:
                    pass
                ser.close()
                callback_ui_error("E31 - No data received during Handshake")
                return

            # read any available bytes
            try:
                chunk = ser.read(256)  # read up to 256 bytes
            except Exception as e:
                try:
                    turn_BL_Detect_Low()
                except:
                    pass
                ser.close()
                callback_ui_error(f"E14 - Serial Port Error during Handshake: {e}")
                return

            if not chunk:
                # no data right now, continue looping
                continue

            # reset handshake timer (we got some data)
            start_time = time.time()

            # append chunk as hex string (exactly like JS Buffer.toString('hex'))
            chunk_hex = chunk.hex()
            received_hex += chunk_hex

            # debug update
            callback_ui_message(f"Received hex length: {len(received_hex)}")

            # wait until we have at least 1024 hex chars (512 bytes)
            if len(received_hex) < REQUIRED_HEX_LENGTH:
                continue

            # Work with the first 1024 hex chars (512 bytes) like JS
            first_block_hex = received_hex[:REQUIRED_HEX_LENGTH]
            try:
                buffer_bytes = bytes.fromhex(first_block_hex)
            except Exception:
                ser.close()
                try:
                    turn_BL_Detect_Low()
                except:
                    pass
                callback_ui_error("Invalid hex data received")
                return

            # SOP / EOP (JS used bufferData[0] and bufferData[509])
            SOP = f"{buffer_bytes[0]:02x}"
            EOP = f"{buffer_bytes[509]:02x}"

            # firmware bytes
            firmware_v1 = buffer_bytes[393]
            firmware_v2 = buffer_bytes[394]

            # Try unencrypted flow first
            try:
                if SOP == "2a" and EOP == "3c":
                    # unencrypted; check CRC
                    crc_calc = calculate_crc16(buffer_bytes[:510])  # int
                    little_end = calculate_little_endian(crc_calc)
                    crc_recv = buffer_bytes[510:512].hex()
                    if little_end != crc_recv:
                        # invalid CRC
                        try:
                            turn_BL_Detect_Low()
                        except:
                            pass
                        ser.close()
                        callback_ui_error("E52 - Invalid Data Received")
                        return
                    is_encryption_enable = get_encryption_flag_from_fw(firmware_v1, firmware_v2)
                else:
                    # encrypted: decrypt the 1024 hex block using AES-CBC (Decrypt)
                    callback_ui_message("Encrypted data received, decrypting...")
                    try:
                        decrypted_hex = decrypt_hex_block(first_block_hex)
                    except Exception as e:
                        ser.close()
                        try:
                            turn_BL_Detect_Low()
                        except:
                            pass
                        callback_ui_error(f"E52 - Decrypt failed: {e}")
                        return

                    # convert decrypted hex to bytes and re-evaluate SOP/EOP/CRC/firmware
                    try:
                        buffer_bytes = bytes.fromhex(decrypted_hex)
                    except Exception as e:
                        ser.close()
                        try:
                            turn_BL_Detect_Low()
                        except:
                            pass
                        callback_ui_error("E52 - Decrypted data invalid hex")
                        return

                    SOP = f"{buffer_bytes[0]:02x}"
                    EOP = f"{buffer_bytes[509]:02x}"
                    firmware_v1 = buffer_bytes[393]
                    firmware_v2 = buffer_bytes[394]

                    if SOP != "2a" or EOP != "3c":
                        ser.close()
                        try:
                            turn_BL_Detect_Low()
                        except:
                            pass
                        callback_ui_error("E52 - Invalid Data Received")
                        return

                    crc_calc = calculate_crc16(buffer_bytes[:510])
                    little_end = calculate_little_endian(crc_calc)
                    crc_recv = buffer_bytes[510:512].hex()
                    if little_end != crc_recv:
                        ser.close()
                        try:
                            turn_BL_Detect_Low()
                        except:
                            pass
                        callback_ui_error("E52 - Invalid Data Received")
                        return

                    is_encryption_enable = get_encryption_flag_from_fw(firmware_v1, firmware_v2)

            except Exception as e:
                ser.close()
                try:
                    turn_BL_Detect_Low()
                except:
                    pass
                callback_ui_error(f"Error validating data: {e}")
                return

            # Passed validation — extract DU & Display numbers
            try:
                du_number, display_number = parse_du_and_display_from_hex(first_block_hex)
            except Exception as e:
                ser.close()
                turn_BL_Detect_Low()
                callback_ui_error(f"Parsing DU/Display failed: {e}")
                return


            # close serial and pull BL pin low like JS
            try:
                ser.close()
            except:
                pass
            try:
                turn_BL_Detect_Low()
            except:
                pass

            callback_ui_message(f"DU detected: {du_number}, Display: {display_number}")

            # Now call DU_Update API to get file list
            server_url = os.getenv("SERVER_URL")
            device_id = os.getenv("DEVICE_ID", "")
            if not server_url:
                callback_ui_error("SERVER_URL not configured")
                return

            callback_ui_message("Querying server for DU update list...")
            try:
                resp = requests.get(
                    f"{server_url}api/dispenserUnit/DU_Update",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "deviceID": f"{device_id}",
                        "duNumber": str(du_number),
                        "displayNumber": str(display_number),
                    },
                    timeout=20,
                )
            except Exception as e:
                callback_ui_error(f"Error contacting server: {e}")
                return

            if resp.status_code != 200:
                # try to parse error message
                try:
                    msg = resp.json().get("message", resp.text)
                except Exception:
                    msg = resp.text
                if isinstance(msg, str) and "No DU Assigned" in msg:
                    callback_ui_error("No DU Assigned")
                else:
                    callback_ui_error(f"DU_Update error: HTTP {resp.status_code}")
                return

            try:
                options = resp.json().get("response")
            except Exception as e:
                callback_ui_error(f"Malformed DU_Update response: {e}")
                return

            # success: return options to UI
            callback_ui_success({
                "duNumber": du_number,
                "displayNumber": display_number,
                "options": options,
                "isEncryptionEnable": is_encryption_enable
            })
            return

    except Exception as exc:
        try:
            turn_BL_Detect_Low()
        except:
            pass
        callback_ui_error(f"Unexpected error: {exc}")
        return


# helpers used above
def _parse_du_and_display(buf: bytes):
    du_number = int.from_bytes(buf[2:10], byteorder="big")
    display_number = int.from_bytes(buf[10:18], byteorder="big")
    return du_number, display_number


def get_encryption_flag_from_fw(fw1: int, fw2: int) -> bool:
    # port of your JS getEncryptionFlag (adjust if your JS uses different logic)
    return get_encryption_flag(fw1, fw2) if 'get_encryption_flag' in globals() else (fw1 >= 11 and fw2 >= 8)
