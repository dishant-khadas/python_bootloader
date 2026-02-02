import os
import requests
from logGenerator import write_log

API_URL = "https://bootloader.czarmetricsystem.com/api/auth/serviceEngineer/phonelogin"

def login_api(phone, password):
    device_id = os.getenv("DEVICE_ID", "UNKNOWN")

    payload = {
        "phoneNo": phone,
        "password": password,
        "deviceID": '41999990'
    }

    print("\n---- LOGIN API CALL ----")
    print("URL:", API_URL)
    print("Payload:", payload)

    try:
        res = requests.post(API_URL, json=payload, timeout=10)

        print("Status Code:", res.status_code)
        print("Raw Response:", res.text)

        try:
            data = res.json()
            print("Parsed JSON:", data)
        except Exception:
            print("JSON Parse Failed")

        if res.status_code == 200:
            data = res.json()
            if "token" in data:
                print("Login Success! Token:", data["token"])
                return True, data["token"]

        print("Login Failed")
        write_log("E-51", "Login Failed", "Failed", "Invalid Credentials", device_id, phone, "", "", "")
        return False, None

    except Exception as e:
        print("API ERROR:", str(e))
        return False, None
