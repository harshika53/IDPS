import requests
import base64

# Replace this with your actual VirusTotal API key
VIRUSTOTAL_API_KEY = "f506c767fc5f3764b4d20bd2d3d104a9d88eaec45c7f3cddb156ef3def82046d"

def check_virustotal(url):
    """Check the URL using VirusTotal API and return threat level."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    # Encode the URL to base64 URL-safe format for VirusTotal API
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    #print(f"Encoded URL Hash: {url_hash}")  # Debugging: Print the URL hash
    
    api_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

    try:
        # Send a GET request to the VirusTotal API
        response = requests.get(api_url, headers=headers)

        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            
            # Extract the number of malicious detections
            positives = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            
            # Determine threat level based on malicious detections
            if positives > 5:
                return "high"
            elif positives > 1:
                return "medium"
            else:
                return "low"
        else:
            # Handle unsuccessful responses
            print(f"Error: Received status code {response.status_code} from VirusTotal API.")
            return "error"
    except Exception as e:
        # Handle request errors
        print(f"Error connecting to VirusTotal: {e}")
        return "error"

