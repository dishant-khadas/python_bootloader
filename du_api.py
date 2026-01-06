import os
import requests

# Base URL fallback
DEFAULT_SERVER_URL = "https://bootloader.czarmetricsystem.com"

def fetch_du_list(token, du_number, display_number):
    """
    Fetches the DU list from the server using the provided token and identifiers.
    Returns: (success: bool, data_or_error: any, is_encryption: bool)
    """
    base_url = os.getenv("SERVER_URL", DEFAULT_SERVER_URL)
    url = f"{base_url.rstrip('/')}/api/dispenserUnit/DU_Update"

    # Device ID from env or fallback (matching auth_api.py fallback)
    device_id = os.getenv("DEVICE_ID", "41999990")

    headers = {
        "Authorization": f"Bearer {token}",
        "deviceID": device_id,
        "duNumber": str(du_number),
        "displayNumber": str(display_number)
    }

    print(f"\n---- FETCH DU LIST API ----")
    print(f"URL: {url}")
    print(f"Headers: {headers}")

    try:
        response = requests.get(url, headers=headers, timeout=15)
        print("Status Code:", response.status_code)
        
        if response.status_code == 200:
            data = response.json()
            # print("Raw Response:", data) # Debugging

            if "response" in data:
                # The 'response' key contains the options/list
                options = data["response"]
                # According to the JS, it just sends options. 
                # We might check for encryption flag if it exists in the root or elsewhere, 
                # but for now let's assume False or look for it.
                # extra safe: check if isEncryptionEnable is in data
                is_enc = data.get("isEncryptionEnable", False)
                return True, options, is_enc
            else:
                return False, "Invalid Response Structure", False
        else:
            print("Error Response:", response.text)
            try:
                err_data = response.json()
                msg = err_data.get("message", f"HTTP {response.status_code}")
            except:
                msg = f"HTTP Error {response.status_code}"
            return False, msg, False

    except Exception as e:
        print(f"Exception fetching DU list: {e}")
        return False, str(e), False
