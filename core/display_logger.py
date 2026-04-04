"""
Display Logger Module for Python Bootloader Application.

This module handles logging of display data received during the 512-byte handshake.
It parses nozzle data, firmware information, and device details, then writes them
to a CSV file for record-keeping.

Log Fields:
    - Serial Number, Date, Time, DU Number, Display Number
    - Display SHA Signature, Firmware Version, Auto Mode, On/Off State
    - 4 Nozzles: ID, Amount, Volume, K-Factor, Timestamp, TXN, FW, SHA

Functions:
    write_display_log: Write display data to CSV file.
"""

import os
import csv
from datetime import datetime
from typing import Optional
from utils.logger import logger
from utils.path_utils import get_log_path
from core.models import DisplaySession, NozzleLog


def write_display_log(hex_data: str) -> None:
    """
    Parse 512-byte hex data and write display information to CSV.
    
    Args:
        hex_data (str): 1024-character hex string (512 bytes) from handshake.
    """
    # Define field positions (matching JS implementation)
    DU_START = 2
    DISPLAY_START = 10
    DISPLAY_END = 18
    FIRMWARE_1 = 19
    FIRMWARE_2 = 21
    
    # Get current timestamp in IST
    now = datetime.now()
    date_str = now.strftime("%d/%m/%Y")
    time_str = now.strftime("%H:%M:%S")
    
    # Parse main fields
    auto_mode = int(hex_data[638], 16)
    onoff = int(hex_data[640:647], 16)
    du_number = int(hex_data[DU_START:DISPLAY_START], 16)
    display_number = int(hex_data[DISPLAY_START:DISPLAY_END], 16)
    display_sha_sign = "0x" + hex_data[22:85]
    firmware1 = int(hex_data[FIRMWARE_1:FIRMWARE_1+1], 16)
    firmware2 = int(hex_data[FIRMWARE_2:FIRMWARE_2+1], 16)
    firmware_version = f"{firmware1}.{firmware2}"
    
    # Parse nozzle data (4 nozzles)
    nozzle_offsets = [87, 223, 359, 495]
    nozzle_data = []
    
    for offset in nozzle_offsets:
        nozzle = {
            'ID': int(hex_data[offset], 16),
            'amount': f"{int(hex_data[offset+1:offset+9], 16)}.{int(hex_data[offset+9:offset+13], 16)}",
            'volume': f"{int(hex_data[offset+13:offset+21], 16)}.{int(hex_data[offset+21:offset+25], 16)}",
            'kfactor': int(hex_data[offset+25:offset+33], 16),
            'date': int(hex_data[offset+33:offset+35], 16),
            'month': int(hex_data[offset+35:offset+37], 16),
            'year': int(hex_data[offset+37:offset+39], 16),
            'hr': int(hex_data[offset+39:offset+41], 16),
            'min': int(hex_data[offset+41:offset+43], 16),
            'sec': int(hex_data[offset+43:offset+45], 16),
            'txn': int(hex_data[offset+45:offset+53], 16),
            'fw': f"{int(hex_data[offset+53:offset+54], 16)}.{int(hex_data[offset+54:offset+55], 16)}",
            'sha': "0x" + hex_data[offset+55:offset+119]
        }
        nozzle_data.append(nozzle)
    
    # Prepare CSV file path (in user-writable ~/.czar-bootloader/)
    csv_path = get_log_path("Display_log.csv")
    
    # Determine serial number
    serial_no = 1
    if os.path.exists(csv_path):
        try:
            with open(csv_path, 'r') as f:
                lines = [line for line in f if line.strip()]
                if len(lines) > 1:  # Has header + data
                    serial_no = len(lines)
        except Exception as e:
            logger.info(f"Error reading display log: {e}")
    header = [
        "SrNO", "Date", "Time", "DuNo", "dispSrNo", "displayShaSign", "firmware", 
        "autoMode", "onoff",
        "Nozzle1_ID", "Nozzle1_Amount", "Nozzle1_Volume", "Nozzle1_KFactor", 
        "Nozzle1_Timestamp", "Nozzle1_TXN", "Nozzle1_FW", "Nozzle1_SHA",
        "Nozzle2_ID", "Nozzle2_Amount", "Nozzle2_Volume", "Nozzle2_KFactor", 
        "Nozzle2_Timestamp", "Nozzle2_TXN", "Nozzle2_FW", "Nozzle2_SHA",
        "Nozzle3_ID", "Nozzle3_Amount", "Nozzle3_Volume", "Nozzle3_KFactor", 
        "Nozzle3_Timestamp", "Nozzle3_TXN", "Nozzle3_FW", "Nozzle3_SHA",
        "Nozzle4_ID", "Nozzle4_Amount", "Nozzle4_Volume", "Nozzle4_KFactor", 
        "Nozzle4_Timestamp", "Nozzle4_TXN", "Nozzle4_FW", "Nozzle4_SHA"
    ]
    
    # Build row data
    row = [
        serial_no, date_str, time_str, du_number, display_number,
        display_sha_sign, firmware_version, auto_mode, onoff
    ]
    
    # Add nozzle data
    for nozzle in nozzle_data:
        timestamp = f"{nozzle['date']}/{nozzle['month']}/{nozzle['year']}-{nozzle['hr']}:{nozzle['min']}:{nozzle['sec']}"
        row.extend([
            nozzle['ID'], nozzle['amount'], nozzle['volume'], nozzle['kfactor'],
            timestamp, nozzle['txn'], nozzle['fw'], nozzle['sha']
        ])
    
    # Write to CSV
    try:
        needs_header = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0
        
        with open(csv_path, 'a', newline='') as f:
            writer = csv.writer(f)
            if needs_header:
                writer.writerow(header)
            writer.writerow(row)
        
        logger.info(f"Display log written: Serial {serial_no}")
        
    except Exception as e:
        logger.info(f"Error writing display log: {e}")

    # ── Write to SQLite3 Display_Session + Nozzle_Log tables ─────────────────
    # Only reached on successful handshake — never called on login/handshake failures
    try:
        session = DisplaySession.create(
            SrNO          = serial_no,
            Date          = date_str,
            Time          = time_str,
            duNumber      = str(du_number),
            displayNumber = str(display_number),
            displayShaSign= display_sha_sign,
            firmware      = float(firmware_version),
            autoMode      = auto_mode,
            onoff         = onoff,
        )
        # Write 4 NozzleLog rows — one per nozzle
        for idx, nozzle in enumerate(nozzle_data, 1):
            timestamp = (
                f"{nozzle['date']}/{nozzle['month']}/{nozzle['year']}"
                f"-{nozzle['hr']}:{nozzle['min']}:{nozzle['sec']}"
            )
            NozzleLog.create(
                session       = session,
                nozzle_number = idx,
                nozzle_ID     = nozzle["ID"],
                Amount        = float(nozzle["amount"]),
                Volume        = float(nozzle["volume"]),
                KFactor       = nozzle["kfactor"],
                Timestamp     = timestamp,
                TXN           = nozzle["txn"],
                FW            = float(nozzle["fw"]),
                SHA           = nozzle["sha"],
            )
        logger.info(f"Display_Session + 4 NozzleLog rows written: Serial {serial_no}")
    except Exception as e:
        logger.error(f"DB write failed (Display_Session/Nozzle_Log): {e}")
