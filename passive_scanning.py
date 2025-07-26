import os
import requests
from dotenv import load_dotenv

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_url_risk(url):
    print("[DEBUG-VT] Running VirusTotal check...")
    if not VIRUSTOTAL_API_KEY:
        print("[DEBUG-VT] ERROR: VirusTotal API key not found.")
        return "error"

    try:
        encoded_url = requests.utils.quote(url, safe='')
        api_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        print(f"[DEBUG-VT] Making request to: {api_url}")

        response = requests.get(api_url, headers=headers, timeout=15)
        print(f"[DEBUG-VT] API Response Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            print(f"[DEBUG-VT] Malicious votes found: {malicious}")
            
            if malicious > 5: return "high"
            elif malicious > 0: return "medium"
            else: return "low"
        else:
            print(f"[DEBUG-VT] API Error Body: {response.text}")
            return "error"
            
    except requests.RequestException as e:
        print(f"[DEBUG-VT] CRITICAL ERROR making request: {e}")
        return "error"