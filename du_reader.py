# # du_reader.py
# import os
# import time
# import requests
# import serial
# from typing import Callable

# from decrypt_utils import decrypt_hex_block
# from du_utils import calculate_crc16, calculate_little_endian
# from gpio_control import turn_BL_Detect_High, turn_BL_Detect_Low

# from dotenv import load_dotenv
# load_dotenv()

# from du_api import fetch_du_list

# # Configurable defaults
# DEFAULT_SERIAL_PORT = os.getenv("SERIAL_PORT", "/dev/ttyS3")
# DEFAULT_BAUDRATE = int(os.getenv("SERIAL_BAUD", "115200"))
# HANDSHAKE_TIMEOUT = 10  # seconds
# REQUIRED_HEX_LENGTH = 1024  # hex chars == 512 bytes


# def get_encryption_flag(fw1: int, fw2: int) -> bool:
#     """
#     Port of getEncryptionFlag (simple heuristic: firmware >= some version).
#     Adjust logic if you have a different rule.
#     """
#     try:
#         return (fw1 >= 11 and fw2 >= 8)
#     except Exception:
#         return False






# def read_du_from_serial(
#     token: str,
#     callback_ui_message: Callable[[str], None],
#     callback_ui_success: Callable[[dict], None],
#     callback_ui_error: Callable[[str], None],
#     serial_port: str = DEFAULT_SERIAL_PORT,
#     baudrate: int = DEFAULT_BAUDRATE,
# ):
#     """
#     Blocking function that does the DU handshake. Call it from a worker thread.

#     Args:
#       token: auth token (Bearer)
#       callback_ui_message: fn(str) for status updates
#       callback_ui_success: fn(dict) on success (receives options from DU_Update API)
#       callback_ui_error: fn(str) on error
#       serial_port: device path (default '/dev/ttyS3')
#       baudrate: int baud

#     Behavior mirrors your JS:
#       - toggle BL_DETECT HIGH
#       - open serial
#       - accumulate hex chunks until >= 1024 chars (512 bytes)
#       - build buffer, check SOP/EOP; if mismatch -> decrypt_hex_block(receivedHex)
#       - check CRC using calculate_crc16() and calculate_little_endian()
#       - determine isEncryptionEnable via firmware bytes
#       - call DU_Update API with headers Authorization Bearer, deviceID, duNumber, displayNumber
#       - callback_ui_success(options) on success
#       - ensures turn_BL_Detect_Low() in error/final branches
#     """

#     try:
#         # raise BL detect high (start handshake)
#         try:
#             turn_BL_Detect_High()
#         except Exception as e:
#             callback_ui_message(f"Warning: turn_BL_Detect_High failed: {e}")

#         # callback_ui_message(f"Opening serial port {serial_port}...")
#         # try:
#         #     ser = serial.Serial(serial_port, baudrate=baudrate, timeout=0.5)
#         # except Exception as e:
#         #     callback_ui_error(f"E14 - Serial Port Error during Handshake: {e}")
#         #     try:
#         #         turn_BL_Detect_Low()
#         #     except:
#         #         pass
#         #     return

#         # received_hex = ""
#         # start_time = time.time()
#         # is_encryption_enable = False
#         # buffer_bytes = b""

#         # callback_ui_message("Waiting for DU...")

#         # while True:
#             # timeout if nothing arrives for HANDSHAKE_TIMEOUT seconds
#             # if time.time() - start_time > HANDSHAKE_TIMEOUT and len(received_hex) == 0:
#             #     try:
#             #         turn_BL_Detect_Low()
#             #     except:
#             #         pass
#             #     ser.close()
#             #     callback_ui_error("E31 - No data received during Handshake")
#             #     return

#             # read any available bytes
#             # try:
#             #     chunk = ser.read(256)  # read up to 256 bytes
#             # except Exception as e:
#             #     try:
#             #         turn_BL_Detect_Low()
#             #     except:
#             #         pass
#             #     ser.close()
#             #     callback_ui_error(f"E14 - Serial Port Error during Handshake: {e}")
#             #     return

#             # if not chunk:
#             #     # no data right now, continue looping
#             #     continue
        
#         # --- DUMMY DATA INJECTION START ---
#         callback_ui_message("Simulating serial data reception...")
#         time.sleep(1) # simulate delay
        
#         # User provided dummy data:
#         # Note: I am stripping whitespace and newlines from the user input.
#         # dummy_data = """
#         # 2a05e69ec000b71b00a37f196c552e9ad401f83bc2776e449d0abe88104f2ca96b31f1d760938e251172c8549f0de36ab1485e22917dc30fa86f33e918742a5b9cd140668bf02da47c135a99ce08e76d3491bf520a7ed81fc645882b9e03a1746fd05cb8197de462900fa53ec18a4d17736b2e98d5f9401ca7568e03c972bf2a649de1305f88a417c67b0d539e41f26ab70cd82599e5134a7f902b6dc158a8f403729c1e6fd5b08842a17d9f306ce4125b780ad194f8235e6ac70db94177a3189e642c0f5588d24b7f139ca0e65a318d026fb1c4990e5772da18f03e85647c2ba9d6419f08e36d1574c8539a0fb24e7a1d90e8665f2ca13899c70b5e742a8df46119b09c536ed1a840720f2bc95d7a1388e460f19e34a7c25b0d6f941872a9e3418f607c1d53b899e42f0a6b459c31d7a180f25e1874c63b9f0da852e16f2590487a1cd4b35f88e9026da59c40721bf0e634887f5a13c299d80e614ba1f52d789e406c1fb70a558ed12374c960a45b9f186a2cd741e8905e13b1779df034a8621c7be450990d5f742a6ec19813a74bf890325d7c1ea46f8819c3532d749f60a138e70b667ad841905e2bc9f418739c0da56f34e188521ab7609f2c4578d40ea1536bc8991d72f03e5f842a9ed741608815c374a90f6d2be19c507a34b81f8853c72d996fa40e1874e5905b13c8417f2a9ed1660fb3749c2da85e18f4603c0e6b
#         # """
#         dummy_data = """e4a54694cc98744a6e097e87840548c08b8b21d854704da83b3cfc4f726f48871d1f6b3e203874c0a020c7b3efcbcce69469e9a1cff36384b90d6a88e1ad9cd91d3b9698c9586dcf52124dca533f37eb91bb4bbe9cba087aae9223d70a4ce3f408ebef9a8d2d643936ee461bec6fd0abaf1bb8e1d527c3982dab90daffb435d0d36d83c579893d08ead524de3aed56dc297c21b6a59b818ba8b0a122f21b8d7c8b870d3dca6ae7a5fae4719683f4d0dd47ec32583b7988ceeed5ccadfe0e4f9d663e7e1b88aa9c7ca9a425afa7e5199f43e6bbd923c4c80f9e81fe2e53d6d32ead4d0b76db2f46b7cd07a10a9294cd03adb45bb4bc8386df4b7610ad1e8d9ad46022bf955a9d21a87d260494db9a15e927300818af66986766ad3526ffd6aee33e2e1b8dfe88a3502cf7f83673a6d5f18cb4726da1f329aa9d0ad9cbb5927aa83defeeaf08efc29b98a6ba1ddf868cfaf1ac087a12e0cb36cb8851f85dc3e117c4d5e68b9c38f0d613026a74969b72ee110d630d3cddbac2bad2c90938ea7265249e7badea4a51855e88bb2e6d20effa53cff993ac78ad16aba45098f2e52b95ebde367b1b007545340c31924673a07f4032eee9433a7398f0de4e6c8110eb3c19fbc86c4ecbca7ae4bc55b9b3b5f273002eb80055142517b40db33eb2106da08c237bf3f27588004154305a295dc0c24c01a280b67ba07893ccf19dc214c446"""
        
#         # Clean up: remove spaces and newlines
#         received_hex = dummy_data.replace(" ", "").replace("\n", "").lower()
        
#         callback_ui_message(f"Dummy data loaded (len: {len(received_hex)})")

        
        
#         # Simulate the 'REQUIRED_HEX_LENGTH' check implicitly, we know it's > 1024 char probably
#         # but let's just proceed to the processing logic which is loop based
        
#         # reset handshake timer (we got some data)
#         # start_time = time.time()

#         # append chunk as hex string (exactly like JS Buffer.toString('hex'))
#         # chunk_hex = chunk.hex()
#         # received_hex += chunk_hex

#         # debug update
#         # callback_ui_message(f"Received hex length: {len(received_hex)}")

#         # wait until we have at least 1024 hex chars (512 bytes)
#         # if len(received_hex) < REQUIRED_HEX_LENGTH:
#         #     continue
        
#         # --- BYPASSING LOOP: JUST RUN ONCE ---
#         if True: # Indent simulated loop body
#         # --- DUMMY DATA INJECTION END ---

#             # Work with the first 1024 hex chars (512 bytes) like JS
#             first_block_hex = received_hex[:REQUIRED_HEX_LENGTH]
#             # try:
#             buffer_bytes = bytes.fromhex(first_block_hex)
#             # except Exception:
#             #     ser.close()
#             #     try:
#             #         turn_BL_Detect_Low()
#             #     except:
#             #         pass
#             #     callback_ui_error("Invalid hex data received")
#             #     return


#             # SOP / EOP (JS used bufferData[0] and bufferData[509])
#             SOP = f"{buffer_bytes[0]:02x}"
#             EOP = f"{buffer_bytes[509]:02x}"
#             print("buffer len : ", len(buffer_bytes))
#             print(f"SOP: {SOP}, EOP: {EOP}")
            

#             # firmware bytes
#             firmware_v1 = buffer_bytes[393]
#             firmware_v2 = buffer_bytes[394]

#             # Logic strictly mirroring JS:
#             # if ( SOP === "2a" && EOP === "3c" ) { ... }
#             # if(SOP != "2a" && EOP != "3c") { ... }
            
#             validated = False

#             if SOP == "2a" and EOP == "3c":
#                 # unencrypted; check CRC
#                 # debug log
#                 print("without encryption")
#                 callback_ui_message("SOP/EOP matched (unencrypted). Checking CRC...")
                
#                 crc_calc = calculate_crc16(buffer_bytes[:510])  # int
#                 little_end = calculate_little_endian(crc_calc)
#                 crc_recv = buffer_bytes[510:512].hex()
                
#                 if little_end == crc_recv:
#                     is_encryption_enable = get_encryption_flag(firmware_v1, firmware_v2)
#                     validated = True
#                 else:
#                     callback_ui_message(f"CRC Mismatch: Calc {little_end} vs Recv {crc_recv}")
#                     # JS sends error "E52-Invalid Data Received"
#                     # ser.close()
#                     try:
#                         turn_BL_Detect_Low()
#                     except:
#                         pass
#                     callback_ui_error("E52 - Invalid Data Received")
#                     return

#             elif SOP != "2a" and EOP != "3c":
#                 # encrypted
#                 print("with encryption")
#                 callback_ui_message("Encrypted data detected (SOP/EOP mismatch)...")
#                 try:
#                     # Decrypt receives hex string
#                     decrypted_hex = decrypt_hex_block(first_block_hex)
#                     # Convert to buffer
#                     buffer_bytes = bytes.fromhex(decrypted_hex)
                    
#                     # Re-check SOP/EOP
#                     SOP = f"{buffer_bytes[0]:02x}"
#                     EOP = f"{buffer_bytes[509]:02x}"
#                     firmware_v1 = buffer_bytes[393]
#                     firmware_v2 = buffer_bytes[394]

#                     if SOP == "2a" and EOP == "3c":
#                         crc_calc = calculate_crc16(buffer_bytes[:510])
#                         little_end = calculate_little_endian(crc_calc)
#                         crc_recv = buffer_bytes[510:512].hex()
                        
#                         if little_end == crc_recv:
#                             is_encryption_enable = get_encryption_flag(firmware_v1, firmware_v2)
#                             # Additional JS step: if (isEncryptionEnable) { ... set KEY_FOR_ENCRYPTION ... }
#                             # But here we just need to pass isEncryptionEnable to the flasher later.
#                             validated = True
#                         else:
#                              callback_ui_error("E52 - Invalid Data Received (CRC fail after decrypt)")
#                              return
#                     else:
#                         # JS doesn't explicitly throw here in the inner block if SOP/EOP fail after decrypt?
#                         # Actually it does: if (SOP === "2a" && EOP === "3c") { ... } else { error }
#                         callback_ui_error("E52 - Invalid Data Received (SOP/EOP fail after decrypt)")
#                         return

#                 except Exception as e:
#                         # ser.close()
#                         try:
#                             turn_BL_Detect_Low()
#                         except:
#                             pass
#                         callback_ui_error(f"E52 - Decrypt failed: {e}")
#                         return

#             else:
#                  # Case where one matches and other doesn't (SOP=2a but EOP!=3c, etc.)
#                  # JS ignores this? Or just falls through?
#                  # logic: if(SOP != "2a" && EOP != "3c")
#                  # This condition is FALSE if SOP=="2a" (regardless of EOP)
#                  # This condition is FALSE if EOP=="3c" (regardless of SOP)
#                  # So if partial match, it does NOTHING in JS logic loop.
#                  # But we are in a while True loop here. If we skip, we should continue to next read?
#                  # However, we've read a block. If it's invalid, we probably should fail or just log and continue?
#                  # JS code has this inside `port.on("data", ...)` accumulating buffer.
#                  # But here we blocked reading until 1024 chars.
#                  # If we return/fail here, we stop the process.
#                  # Let's fail safe.
#                  callback_ui_message(f"Invalid SOP/EOP combination: {SOP}/{EOP}")
#                  # ser.close()
#                  turn_BL_Detect_Low()
#                  callback_ui_error("E52 - Invalid Data Received (SOP/EOP Mismatch)")
#                  return

#             if not validated:
#                  # Should have returned error by now if not validated
#                  # ser.close()
#                  try:
#                     turn_BL_Detect_Low()
#                  except:
#                     pass
#                  callback_ui_error("E52 - Verification Failed")
#                  return

#             # If we are here, data is valid and buffer_bytes contains the correct data (decrypted if needed)
#             # Re-convert buffer_bytes to hex string for parsing if we want consistency, 
#             # OR just use buffer_bytes indices. 
#             # parse_du_and_display expects HEX string.
#             # If we decrypted, buffer_bytes is decrypted. We should convert it back to hex for parsing function.
#             final_hex = buffer_bytes.hex()
            
#             try:
#                 du_number, display_number = parse_du_and_display_from_hex(final_hex)
#             except Exception as e:
#                 # ser.close()
#                 try:
#                     turn_BL_Detect_Low()
#                 except:
#                     pass
#                 callback_ui_error(f"Parsing DU/Display failed: {e}")
#                 return


#             # close serial and pull BL pin low like JS
#             # try:
#             #     ser.close()
#             # except:
#             #     pass
#             try:
#                 turn_BL_Detect_Low()
#             except:
#                 pass

#             callback_ui_message(f"DU detected: {du_number}, Display: {display_number}")

#             # Now call DU_Update API to get file list
#             callback_ui_message("Querying server for DU update list...")
            
#             success, options_or_msg, _ = fetch_du_list(token, du_number, display_number)
            
#             if not success:
#                  if "No DU Assigned" in str(options_or_msg):
#                       callback_ui_error("No DU Assigned")
#                  else:
#                       callback_ui_error(f"DU_Update error: {options_or_msg}")
#                  return
            
#             options = options_or_msg

#             # success: return options to UI
#             callback_ui_success({
#                 "duNumber": du_number,
#                 "displayNumber": display_number,
#                 "options": options,
#                 "isEncryptionEnable": is_encryption_enable
#             })
#             return

#     except Exception as exc:
#         try:
#             turn_BL_Detect_Low()
#         except:
#             pass
#         callback_ui_error(f"Unexpected error: {exc}")
#         return



# # helpers used above

# def parse_du_and_display_from_hex(hex_str: str):
#     """
#     EXACT JS BEHAVIOR:
#     duNumber     = Number("0x" + receivedData.slice(2, 10))
#     displayNumber= Number("0x" + receivedData.slice(10,18))
#     """
#     du_hex = hex_str[2:10]          # hex characters, not bytes
#     display_hex = hex_str[10:18]

#     return int(du_hex, 16), int(display_hex, 16)

# du_reader.py
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
                decrypted_hex = decrypt_hex_block(first_block_hex)
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
                        is_encryption_enable = get_encryption_flag(firmware_v1, firmware_v2)
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
        callback_ui_message("Querying server for DU update list...")
        
        success, options_or_msg, _ = fetch_du_list(token, du_number, display_number)
        
        if not success:
            if "No DU Assigned" in str(options_or_msg):
                callback_ui_error("No DU Assigned")
            else:
                callback_ui_error(f"DU_Update error: {options_or_msg}")
            return
        
        options = options_or_msg

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

def parse_du_and_display_from_hex(hex_str: str):
    """
    EXACT JS BEHAVIOR:
    duNumber     = Number("0x" + receivedData.slice(2, 10))
    displayNumber= Number("0x" + receivedData.slice(10,18))
    """
    du_hex = hex_str[2:10]          # hex characters, not bytes
    display_hex = hex_str[10:18]

    return int(du_hex, 16), int(display_hex, 16)







