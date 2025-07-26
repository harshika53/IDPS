import os
import requests
from dotenv import load_dotenv

# Load API key from .env file
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("5fa54f5b2c07367e5f6796db0a5938ff389b1b69449d6d8deaa5347142051727")

def check_url_risk(url):
    """
    Checks the URL using the VirusTotal API and returns a risk level.
    """
    if not VIRUSTOTAL_API_KEY:
        print("Error: VirusTotal API key not found.")
        return "error"

    # 1. The input 'url' is encoded to be safely used in a URL.
    # This turns characters like '/' and ':' into their %xx equivalents.
    encoded_url = requests.utils.quote(url, safe='')

    # 2. Python's f-string inserts the value of the 'encoded_url' variable here.
    # THIS LINE IS CORRECT. DO NOT CHANGE IT.
    api_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            # This logic checks how many security vendors flagged the URL as malicious.
            positives = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            
            if positives > 5:
                return "high"
            elif positives > 0: # Even one flag is medium risk
                return "medium"
            else:
                return "low" # No malicious flags
        else:
            print(f"Error from VirusTotal API: Status {response.status_code}")
            return "error"
            
    except requests.RequestException as e:
        print(f"Error making request to VirusTotal: {e}")
        return "error"

