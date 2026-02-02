import os
import csv
import datetime
import subprocess
import requests

API_URL = f"{os.getenv('SERVER_URL')}api/logs/data-log"
written_log = False
next_serial_number = 1
get_ip_script_path=""
csvfile_path = ""





def generateLog(errorCode, errorName, payload):
    """
    Sends log payload to Node.js server
    """

    request_payload = {
        "errorCode": errorCode,
        "errorName": errorName,
        "logData": payload
    }

    try:
        res = requests.post(
            API_URL,
            json=request_payload,
            timeout=10
        )

        print("[LOG API] Status Code:", res.status_code)
        print("[LOG API] Response:", res.text)

    except requests.exceptions.Timeout:
        print("[LOG API] Request timed out")

    except requests.exceptions.ConnectionError:
        print("[LOG API] Server unreachable")

    except Exception as e:
        print("[LOG API] Unexpected error:", str(e))



def write_log(
    errorCode,
    errorName,
    result,
    description,
    device_id,
    phoneNo,
    duNumber,
    displayNumber,
    fileName,
):
    global written_log, next_serial_number

    if written_log:
        return

    data_sent = 0
    now = datetime.datetime.now()

    dateString = now.strftime("%d-%m-%Y")
    timeString = now.strftime("%H:%M:%S")

    year = now.year
    month = f"{now.month:02d}"
    day = f"{now.day:02d}"
    hours = f"{now.hour:02d}"
    minutes = f"{now.minute:02d}"
    seconds = f"{now.second:02d}"

    # ---- Read last serial ----
    try:
        if os.path.exists(csvfile_path):
            with open(csvfile_path, "r") as f:
                rows = list(csv.reader(f))
                if rows:
                    next_serial_number = int(rows[-1][0]) + 1
                else:
                    next_serial_number = 1
    except Exception as e:
        print("E41 - Log File not Found:", e)
        return

    # ---- Get IP ----
    try:
        ip = subprocess.check_output(
            ["python3", get_ip_script_path],
            text=True
        ).strip()
    except Exception:
        ip = "UNKNOWN"

    # ---- Log ID ----
    logID = f"{device_id}_{year-2000}{month}{day}{hours}{minutes}{seconds}_{next_serial_number}"

    # ---- Write CSV ----
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

    try:
        with open(csvfile_path, "a", newline="") as f:
            csv.writer(f).writerow(csv_row)
        print("File has been written")
    except Exception as e:
        print("E43 - Error writing Log:", e)
        return

    written_log = True

    # ---- Payload for API ----
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
    }

    # ---- Send to Node.js server ----
    generateLog(errorCode, errorName, log_payload)
