from flask import Flask, request, jsonify
import requests
from bs4 import BeautifulSoup
from urls import add_to_whitelist, add_to_blacklist, get_whitelisted, get_blacklisted
import backend.redis_config as redis_config

app = Flask(__name__)

# VirusTotal API key
VIRUSTOTAL_API_KEY = "f506c767fc5f3764b4d20bd2d3d104a9d88eaec45c7f3cddb156ef3def82046d"

# Use the redis_client from redis_config
redis_client = redis_config.redis_client  # Get the client from redis_config

def check_virustotal(url):
    """Check the URL using VirusTotal API and return threat level."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    encoded_url = requests.utils.quote(url, safe='')
    api_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        positives = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        if positives > 5:
            return "high"
        elif positives > 1:
            return "medium"
    return "low"

def scrape_url_content(url):
    """Perform web scraping to analyze URL content."""
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        # Perform analysis on `soup` content (not fully implemented here)
        # Return a placeholder risk level based on scraping
        return "low"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/passive_scan', methods=['POST'])
def passive_scan():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    virus_total_risk = check_virustotal(url)
    web_scrape_risk = scrape_url_content(url)

    return jsonify({
        "url": url,
        "virus_total_risk": virus_total_risk,
        "web_scrape_risk": web_scrape_risk
    })

@app.route('/add_to_whitelist', methods=['POST'])
def whitelist_url():
    url = request.json.get('url')
    if add_to_whitelist(url, redis_client):
        return jsonify({"message": "URL added to whitelist successfully!"}), 200
    return jsonify({"message": "URL is already in whitelist!"}), 400

@app.route('/add_to_blacklist', methods=['POST'])
def blacklist_url():
    url = request.json.get('url')
    if add_to_blacklist(url, redis_client):
        return jsonify({"message": "URL added to blacklist successfully!"}), 200
    return jsonify({"message": "URL is already in blacklist!"}), 400

@app.route('/get_whitelist', methods=['GET'])
def get_whitelist():
    urls = get_whitelisted(redis_client)
    return jsonify({"whitelisted_urls": urls}), 200

@app.route('/get_blacklist', methods=['GET'])
def get_blacklist():
    urls = get_blacklisted(redis_client)
    return jsonify({"blacklisted_urls": urls}), 200

if __name__ == '__main__':
    app.run(debug=True)
