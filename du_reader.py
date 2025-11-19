import serial
import time
import binascii
import requests
import threading
import os
import csv
from datetime import datetime

# ---------------------------------------------------
# Helper functions (you must fill logic for THESE)
# ---------------------------------------------------

def calculate_crc16(data_bytes):
    # TODO: implement same CRC16 as JS
    return "0000"

def calculate_little_endian(crc_value: int) -> str:
    """
    Convert integer CRC into a 2-byte little-endian hex string (lowercase).
    Equivalent to JS:
    ((crc >> 8) | ((crc & 0xFF) << 8)).toString(16).padStart(4, "0")
    """
    if not isinstance(crc_value, int):
        # If accidentally passed hex string (like "abcd") convert it
        crc_value = int(crc_value, 16)

    le = ((crc_value >> 8) | ((crc_value & 0xFF) << 8)) & 0xFFFF
    return f"{le:04x}"


def decrypt_hex(hex_string):
    # TODO: implement Python equivalent for Decrypt() JS function
    return hex_string

def get_encryption_flag(fw1, fw2):
    # TODO: replicate getEncryptionFlag() from JS
    return False

# ---------------------------------------------------
# Main DU Read Logic
# ---------------------------------------------------

def read_du_from_serial(token, callback_ui_message, callback_ui_success):
    """
    callback_ui_message(msg) → send status to UI
    callback_ui_success(data) → send final parsed data to UI
    """

    ser = serial.Serial("/dev/ttyAMA0", 115200, timeout=0.1)
    received = ""
    start_time = time.time()

    callback_ui_message("Waiting for DU...")

    # ---------------------------
    # Receive up to 10 seconds
    # ---------------------------
    while True:
        if time.time() - start_time > 10:
            callback_ui_message("E31 - No data received during Handshake")
            ser.close()
            return

        if ser.in_waiting:
            data = ser.read(ser.in_waiting)
            received += binascii.hexlify(data).decode()
            # print("Received:", received)

        if len(received) >= 1024:
            break

        time.sleep(0.05)

    # --------------------------------
    # now parse the first 1024 bytes
    # --------------------------------
    buf = bytes.fromhex(received[:1024*2])

    SOP = buf[0]
    EOP = buf[509]
    fw1 = buf[393]
    fw2 = buf[394]

    encrypted = False

    # --------------------------------
    # Check if encrypted or not
    # --------------------------------
    if SOP == 0x2A and EOP == 0x3C:
        # unencrypted
        crc_calc = calculate_crc16(buf[:510])
        if calculate_little_endian(crc_calc) != buf[510:512].hex():
            callback_ui_message("E52 - Invalid Data Received")
            ser.close()
            return
        encrypted = False
    else:
        encrypted = True
        decrypted_hex = decrypt_hex(received[:1024*2])
        buf = bytes.fromhex(decrypted_hex)

        SOP = buf[0]
        EOP = buf[509]

        crc_calc = calculate_crc16(buf[:510])
        if calculate_little_endian(crc_calc) != buf[510:512].hex():
            callback_ui_message("E52 - Invalid Encrypted Data")
            ser.close()
            return

    # --------------------------------
    # Extract fields
    # --------------------------------

    du_number = int(buf[2:10].hex(), 16)
    display_number = int(buf[10:18].hex(), 16)
    autoMode = buf[638]
    onoff = int(buf[640:647].hex(), 16)

    nozzle_offsets = [87, 223, 359, 495]
    nozzles = []

    for base in nozzle_offsets:
        ID = buf[base]
        amount = "{}.{}".format(
            int(buf[base+1 : base+9].hex(),16),
            int(buf[base+9 : base+13].hex(),16)
        )
        volume = "{}.{}".format(
            int(buf[base+13 : base+21].hex(),16),
            int(buf[base+21 : base+25].hex(),16)
        )
        kfactor = int(buf[base+25 : base+33].hex(),16)
        date = buf[base+33]
        month = buf[base+35]
        year = buf[base+37]
        hr = buf[base+39]
        mn = buf[base+41]
        sec = buf[base+43]
        txn = int(buf[base+45 : base+53].hex(),16)
        fw = f"{buf[base+53]}.{buf[base+54]}"
        sha = buf[base+55 : base+119].hex()

        nozzles.append({
            "ID": ID,
            "amount": amount,
            "volume": volume,
            "kfactor": kfactor,
            "timestamp": f"{date}/{month}/{year}-{hr}:{mn}:{sec}",
            "txn": txn,
            "fw": fw,
            "sha": sha
        })

    # --------------------------------
    # Write CSV log
    # --------------------------------
    log_path = "Display_log.csv"
    write_header = not os.path.exists(log_path)

    with open(log_path, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["SrNo","Date","Time","DU","Display","autoMode","onoff","NozzleData"])

        now = datetime.now()
        nozzle_json = str(nozzles)
        writer.writerow([
            1, now.strftime("%d-%m-%Y"), now.strftime("%H:%M:%S"),
            du_number, display_number, autoMode, onoff, nozzle_json
        ])

    # --------------------------------
    # Send DU Update to Server
    # --------------------------------

    SERVER_URL = os.getenv("SERVER_URL")
    TOKEN = token
    DEVICE_ID = os.getenv("DEVICE_ID")

    try:
        url = f"{SERVER_URL}api/dispenserUnit/DU_Update"
        headers = {
            "Authorization": f"Bearer {TOKEN}",
            "deviceID": DEVICE_ID,
            "duNumber": str(du_number),
            "displayNumber": str(display_number)
        }

        resp = requests.get(url, headers=headers)
        options = resp.json()["response"]

        ser.close()

        callback_ui_success(options)

    except Exception as e:
        callback_ui_message(f"Error contacting server: {e}")
        ser.close()
