"""
Audit Log Generator Module for Python Bootloader Application.

This module provides AUDIT LOGGING — structured error/event tracking for
firmware update operations. It writes to both a local CSV file and a
remote API endpoint.

Logging Architecture (3 systems, different purposes):
    1. logger (utils/logger.py) — Python logging for operational debug output
    2. write_log (this module) — Audit trail: CSV + remote API for error tracking
    3. write_display_log (display_logger.py) — Hardware data CSV from handshake

Log Fields:
    - Serial Number, Log ID, Phone Number, IP Address
    - Date, Time, DU Number, Display Number
    - File Name, Result, Error Description

Functions:
    get_device_ip: Get the device's local IP address.
    generateLog: Send log payload to remote server.
    write_log: Write log entry to CSV and send to server.
"""

import os
import csv
import datetime
import socket
import requests
from utils.logger import logger
from utils.path_utils import get_log_path
from config import config

# Audit logging API endpoint — loaded from centralized config
# API_URL = config.API_URL
API_URL = os.getenv("SERVER_URL")

# Global counter for log serial numbers
next_serial_number = 1

# Path to local CSV log file (in user-writable ~/.czar-bootloader/)
csvfile_path = get_log_path("logs.csv")


def get_device_ip() -> str:
    """
    Get the device's local IP address by creating a UDP socket connection.
    
    Uses a socket connection to Google DNS (8.8.8.8) to determine the local
    IP address. No actual data is sent.
    
    Returns:
        str: The device's local IP address, or "UNKNOWN" if detection fails.
    """
    try:
        # Create a socket and connect to an external address (doesn't actually send data)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "UNKNOWN"


def generateLog(errorCode: str, payload: dict) -> None:
    """
    Send a log payload to the remote Node.js logging server.
    
    Makes a POST request to the logging API with the error code
    and log payload. This is called after writing to the local CSV.
    
    Args:
        errorCode (str): The error code (e.g., "E-51", "E-15").
        payload (dict): Dictionary containing log data fields (includes errorCode).
    """
    logger.info("Generate log function called!")
    #     "logData": payload
    # }

    logger.info(f"Payload to Send :  {payload}")
    try:
        res = requests.post(
            # f"{API_URL}/api/logs/data-log",
            f"{API_URL}api/logs/data-log",
            # json=request_payload,
            json=payload,
            timeout=10
        )

        logger.info(f"[LOG API] Status Code: {res.status_code}")
        logger.info(f"[LOG API] Response: {res.text}")

    except requests.exceptions.Timeout:
        logger.info("[LOG API] Request timed out")

    except requests.exceptions.ConnectionError:
        logger.info("[LOG API] Server unreachable")

    except Exception as e:
        logger.error(f"[LOG API] Unexpected error: {str(e)}")


def write_log(
    errorCode: str,
    errorName: str,
    result: str,
    description: str,
    device_id: str,
    phoneNo: str,
    duNumber: str,
    displayNumber: str,
    fileName: str,
) -> None:
    """
    Write a log entry to the local CSV file and send to remote server.
    
    Creates a unique log ID based on device ID and timestamp, writes the
    log entry to the local CSV file, and then sends it to the remote
    logging server via generateLog().
    
    Args:
        errorCode (str): Error code for categorization (e.g., "E-51").
        errorName (str): Human-readable error name.
        result (str): Result status (e.g., "Failed", "Success").
        description (str): Detailed description of the event.
        device_id (str): Unique device identifier.
        phoneNo (str): User's phone number.
        duNumber (str): Dispenser unit serial number.
        displayNumber (str): Display serial number.
        fileName (str): Name of the firmware file being processed.
        
    Note:
        If CSV writing fails, the function still attempts to send logs
        to the remote server for redundancy.
    """
    global next_serial_number

    data_sent = 0
    now = datetime.datetime.now()

    # Format date and time strings
    dateString = now.strftime("%d-%m-%Y")
    timeString = now.strftime("%H:%M:%S")

    # Extract individual time components for log ID
    year = now.year
    month = f"{now.month:02d}"
    day = f"{now.day:02d}"
    hours = f"{now.hour:02d}"
    minutes = f"{now.minute:02d}"
    seconds = f"{now.second:02d}"

    logger.info("Write log functin called....")
    print(f"CSV Log Path: {csvfile_path}")
    print("path Exist : ",{os.path.exists(csvfile_path)})

    # Read last serial number from existing CSV
    try:
        if os.path.exists(csvfile_path):
            with open(csvfile_path, "r") as f:
                rows = list(csv.reader(f))
                if rows:
                    last_row = rows[-1][0]

                    if last_row.isdigit():
                        next_serial_number = int(last_row) + 1
                    else:
                        next_serial_number = 1
                else:
                    next_serial_number = 1
                # if rows:
                #     next_serial_number = int(rows[-1][0]) + 1
                # else:
                #     next_serial_number = 1
    except Exception as e:
        logger.info(f"E41 - Log File not Found: {e}")
        return

    # Get device IP address
    ip = get_device_ip()

    # Generate unique log ID: deviceID_YYMMDDHHMMSS_serialNumber
    logID = f"{device_id}_{year-2000}{month}{day}{hours}{minutes}{seconds}_{next_serial_number}"

    # Prepare CSV row
    csv_row = [
        next_serial_number,
        logID,
        phoneNo,
        ip,
        dateString,
        timeString,
        duNumber,
        displayNumber,
        fileName,
        result,
        description,
        data_sent,
    ]
    
    # Prepare API payload
    log_payload = {
        "Log_ID": logID,
        "phoneNo": phoneNo,
        "IP_Address": ip,
        "Date": dateString,
        "Time": timeString,
        "DISPENSER_Serial_Number": duNumber,
        "DISPLAY_Serial_Number": displayNumber,
        "FileName": fileName,
        "Result": result,
        "Error_Description": description,
        "errorCode": errorCode,
    }
    
    # Write to CSV and send to server
    try:
        with open(csvfile_path, "a", newline="") as f:
            csv.writer(f).writerow(csv_row)
        logger.info("File has been written")
        generateLog(errorCode, log_payload)
    except Exception as e:
        logger.info(f"E43 - Error writing Log: {e}")
        generateLog(errorCode, log_payload)
        return
