import requests

API_URL = f"{os.getenv('SERVER_URL')}api/logs/data-log"


def generateLog(errorCode, errorName, payload):
    
    try:
        res = requests.post(API_URL, json=payload, timeout=10)
        print("Log Generation Response Status Code:", res.status_code)
        print("Log Generation Response Text:", res.text)
    except Exception as e:
        print("Error generating log:", str(e))