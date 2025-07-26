import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env file at the start
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_url_risk(url):
    """
    Checks the URL using the VirusTotal API and returns a risk level.
    This function now correctly loads the API key from your .env file.
    """
    if not VIRUSTOTAL_API_KEY:
        print("Error: VIRUSTOTAL_API_KEY not found in .env file.")
        return "error" # Return an error state

    # Encode the URL to be safe for the API request
    try:
        encoded_url = requests.utils.quote(url, safe='')
    except Exception:
        # Handle cases where the URL is malformed
        return "error"

    api_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    headers = { "x-apikey": VIRUSTOTAL_API_KEY }

    try:
        response = requests.get(api_url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            # Check how many security vendors flagged the URL as malicious
            malicious_votes = analysis_stats.get("malicious", 0)
            
            if malicious_votes > 5:
                return "high"
            elif malicious_votes > 0:
                return "medium"
            else:
                return "low" # Considered safe
        else:
            print(f"VirusTotal API Error: Status {response.status_code} - {response.text}")
            return "error"
            
    except requests.RequestException as e:
        print(f"Error during VirusTotal request: {e}")
        return "error"
