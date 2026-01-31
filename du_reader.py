import os
import time
import requests
import serial
from typing import Callable

from decrypt_utils import decrypt_hex_block
from du_utils import calculate_crc16, calculate_little_endian
from gpio_control import turn_BL_Detect_High, turn_BL_Detect_Low, turn_display_On, turn_display_Off

from dotenv import load_dotenv
load_dotenv()

from du_api import fetch_du_list

# Configurable defaults
DEFAULT_SERIAL_PORT = os.getenv("SERIAL_PORT", "/dev/ttyAMA0")
DEFAULT_BAUDRATE = int(os.getenv("SERIAL_BAUD", "115200"))
HANDSHAKE_TIMEOUT = 10  # seconds
REQUIRED_HEX_LENGTH = 1024  # hex chars == 512 bytes

# Encryption key location in the 512-byte data (indices 395 to 427, 32 bytes)
ENCRYPTED_KEY_START = 395
ENCRYPTED_KEY_END = 427  # exclusive, so bytes[395:427] gives 32 bytes


def get_encryption_flag(fw1: int, fw2: int) -> bool:
    """
    Port of getEncryptionFlag (simple heuristic: firmware >= some version).
    Adjust logic if you have a different rule.
    """
    try:
        return (fw1 >= 11 and fw2 >= 8)
    except Exception:
        return False






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
            turn_display_On()
            
        except Exception as e:
            callback_ui_message(f"Warning: turn_BL_Detect_High failed: {e}")

        # Open serial port
        callback_ui_message(f"Opening serial port {serial_port}...")
        try:
            ser = serial.Serial(serial_port, baudrate=baudrate, timeout=0.5)
        except Exception as e:
            callback_ui_error(f"E14 - Serial Port Error during Handshake: {e}")
            try:
                turn_BL_Detect_Low()
                turn_display_Off()
            except:
                pass
            return

        received_hex = ""
        start_time = time.time()
        is_encryption_enable = False
        encryption_key = None  # Will store the 32-byte encryption key if data is encrypted
        SERIAL_TIMEOUT = 15  # 15 seconds timeout

        callback_ui_message("Waiting for DU data...")

        while True:
            # Check for timeout (15 seconds with no data at all)
            elapsed = time.time() - start_time
            if elapsed > SERIAL_TIMEOUT and len(received_hex) == 0:
                try:
                    turn_BL_Detect_Low()
                    turn_display_Off()
                except:
                    pass
                ser.close()
                callback_ui_error("E31 - No data received during Handshake (15s timeout)")
                return

            # Also timeout if we've been waiting too long even with partial data
            if elapsed > SERIAL_TIMEOUT:
                try:
                    turn_BL_Detect_Low()
                    turn_display_Off()
                except:
                    pass
                ser.close()
                callback_ui_error(f"E31 - Timeout: Only received {len(received_hex)} hex chars, need {REQUIRED_HEX_LENGTH}")
                return

            # Read any available bytes
            try:
                chunk = ser.read(256)  # read up to 256 bytes at a time
            except Exception as e:
                try:
                    turn_BL_Detect_Low()
                    turn_display_Off()
                except:
                    pass
                ser.close()
                callback_ui_error(f"E14 - Serial Port Error during Handshake: {e}")
                return

            if not chunk:
                # No data right now, continue looping
                continue

            # Append chunk as hex string (exactly like JS Buffer.toString('hex'))
            chunk_hex = chunk.hex()
            received_hex += chunk_hex

            # Debug update
            callback_ui_message(f"Received hex length: {len(received_hex)}")

            # Check if we have enough data (at least 1024 hex chars = 512 bytes)
            if len(received_hex) >= REQUIRED_HEX_LENGTH:
                # We have enough data, close serial and proceed
                ser.close()
                callback_ui_message(f"Data received (len: {len(received_hex)})")
                break

        # Process the received data
        # Work with the first 1024 hex chars (512 bytes) like JS
        first_block_hex = received_hex[:REQUIRED_HEX_LENGTH]
        buffer_bytes = bytes.fromhex(first_block_hex)

        # SOP / EOP (JS used bufferData[0] and bufferData[509])
        SOP = f"{buffer_bytes[0]:02x}"
        EOP = f"{buffer_bytes[509]:02x}"
        print("buffer len : ", len(buffer_bytes))
        print(f"SOP: {SOP}, EOP: {EOP}")

        # firmware bytes
        firmware_v1 = buffer_bytes[393]
        firmware_v2 = buffer_bytes[394]

        # Logic strictly mirroring JS:
        # if ( SOP === "2a" && EOP === "3c" ) { ... }
        # if(SOP != "2a" && EOP != "3c") { ... }
        
        validated = False

        if SOP == "2a" and EOP == "3c":
            # unencrypted; check CRC
            print("without encryption")
            callback_ui_message("SOP/EOP matched (unencrypted). Checking CRC...")
            
            crc_calc = calculate_crc16(buffer_bytes[:510])  # int
            little_end = calculate_little_endian(crc_calc)
            crc_recv = buffer_bytes[510:512].hex()
            
            if little_end == crc_recv:
                is_encryption_enable = get_encryption_flag(firmware_v1, firmware_v2)
                validated = True
            else:
                callback_ui_message(f"CRC Mismatch: Calc {little_end} vs Recv {crc_recv}")
                try:
                    turn_BL_Detect_Low()
                    turn_display_Off()
                except:
                    pass
                callback_ui_error("E52 - Invalid Data Received")
                return

        elif SOP != "2a" and EOP != "3c":
            # encrypted
            print("with encryption")
            callback_ui_message("Encrypted data detected (SOP/EOP mismatch)...")
            try:
                # Decrypt receives hex string
                print("first_block_hex:", first_block_hex)
                decrypted_hex = decrypt_hex_block(first_block_hex)
                print("decrypted_hex:", decrypted_hex)
                # Convert to buffer
                buffer_bytes = bytes.fromhex(decrypted_hex)
                
                # Re-check SOP/EOP
                SOP = f"{buffer_bytes[0]:02x}"
                EOP = f"{buffer_bytes[509]:02x}"
                firmware_v1 = buffer_bytes[393]
                firmware_v2 = buffer_bytes[394]

                if SOP == "2a" and EOP == "3c":
                    crc_calc = calculate_crc16(buffer_bytes[:510])
                    little_end = calculate_little_endian(crc_calc)
                    crc_recv = buffer_bytes[510:512].hex()
                    
                    if little_end == crc_recv:
                        is_encryption_enable = True
                        # Extract encryption key from bytes 395-427 (32 bytes) - this key is encrypted
                        encrypted_key_bytes = buffer_bytes[ENCRYPTED_KEY_START:ENCRYPTED_KEY_END]
                        print(f"Extracted encrypted key (hex): {encrypted_key_bytes.hex()}")
                        
                        # Decrypt the key using AES-256-CBC with keys from encKey.py
                        try:
                            decrypted_key_hex = decrypt_hex_block(encrypted_key_bytes.hex())
                            encryption_key = bytes.fromhex(decrypted_key_hex)
                            print(f"Decrypted encryption key (hex): {encryption_key.hex()}")
                        except Exception as decrypt_err:
                            print(f"Warning: Failed to decrypt encryption key: {decrypt_err}")
                            # Fallback to using the raw extracted key
                            encryption_key = encrypted_key_bytes
                        
                        validated = True
                    else:
                        callback_ui_error("E52 - Invalid Data Received (CRC fail after decrypt)")
                        return
                else:
                    callback_ui_error("E52 - Invalid Data Received (SOP/EOP fail after decrypt)")
                    return

            except Exception as e:
                try:
                    turn_BL_Detect_Low()
                except:
                    pass
                callback_ui_error(f"E52 - Decrypt failed: {e}")
                return

        else:
            # Case where one matches and other doesn't (SOP=2a but EOP!=3c, etc.)
            callback_ui_message(f"Invalid SOP/EOP combination: {SOP}/{EOP}")
            turn_BL_Detect_Low()
            callback_ui_error("E52 - Invalid Data Received (SOP/EOP Mismatch)")
            return

        if not validated:
            try:
                turn_BL_Detect_Low()
            except:
                pass
            callback_ui_error("E52 - Verification Failed")
            return

        # If we are here, data is valid and buffer_bytes contains the correct data (decrypted if needed)
        final_hex = buffer_bytes.hex()
        
        try:
            du_number, display_number = parse_du_and_display_from_hex(final_hex)
        except Exception as e:
            try:
                turn_BL_Detect_Low()
            except:
                pass
            callback_ui_error(f"Parsing DU/Display failed: {e}")
            return

        try:
            turn_BL_Detect_Low()
        except:
            pass

        callback_ui_message(f"DU detected: {du_number}, Display: {display_number}")

        # Now call DU_Update API to get file list
        # callback_ui_message("Querying server for DU update list...")
        
        success, options_or_msg, _ = fetch_du_list(token, du_number, display_number)
        
        if not success:
            if "No DU Assigned" in str(options_or_msg):
                callback_ui_error("No DU Assigned")
            else:
                callback_ui_error(f"DU_Update error: {options_or_msg}")
            turn_display_Off();
            return
        
        options = options_or_msg

        # success: return options to UI
        callback_ui_success({
            "duNumber": du_number,
            "displayNumber": display_number,
            "options": options,
            "isEncryptionEnable": is_encryption_enable,
            "encryptionKey": encryption_key  # 32-byte key or None
        })
        return

    except Exception as exc:
        try:
            turn_BL_Detect_Low()
            turn_display_Off()
        except:
            pass
        callback_ui_error(f"Unexpected error: {exc}")
        return



# helpers used above

def parse_du_and_display_from_hex(hex_str: str):
    """
    EXACT JS BEHAVIOR:
    duNumber     = Number("0x" + receivedData.slice(2, 10))
    displayNumber= Number("0x" + receivedData.slice(10,18))
    """
    du_hex = hex_str[2:10]          # hex characters, not bytes
    display_hex = hex_str[10:18]

    return int(du_hex, 16), int(display_hex, 16)







