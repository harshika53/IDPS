from flask import Flask, request, jsonify, render_template
import requests
import os
from bs4 import BeautifulSoup
from urls import add_to_whitelist, add_to_blacklist, get_whitelisted, get_blacklisted
import redis_config as redis_config
from passive_scanning import check_virustotal
from webscrapping import scrape_and_has_form
from scanner import check_url, scrape_and_scan 
from utility import send_alert, log_scan_result
from flask import send_from_directory, jsonify

# Initialize Flask app
app = Flask(__name__) 

# Static folder where CSV files are stored
STATIC_FOLDER = 'static'

# VirusTotal API key
VIRUSTOTAL_API_KEY = "5fa54f5b2c07367e5f6796db0a5938ff389b1b69449d6d8deaa5347142051727"  # Ensure the API key is correct and kept secure

# Serve the main HTML page
@app.route('/')
def home():
    """
    Serves the main HTML page.
    """
    return render_template('demopg.html')  # Renders demopg.html from the templates folder

from flask import send_from_directory, abort

# Route to serve CSV files (whitelist, blacklist, admin_data)
@app.route('/view_csv/<filename>')
def view_csv(filename):
    file_path = os.path.join(STATIC_FOLDER, filename)

    # Check if the file exists and ensure it's a CSV
    if os.path.exists(file_path) and filename.endswith('.csv'):
        # Serve the file with the correct MIME type
        return send_from_directory(STATIC_FOLDER, filename, as_attachment=True, mimetype='text/csv')

    # If the file is not found, return a custom error message
    return f"Failed to load {filename}. The file doesn't exist.", 404


# Route to perform passive scan on a URL
@app.route('/passive_scan', methods=['POST'])
def passive_scan():
    """
    Scans a URL for suspicious patterns and web content.
    """
    data = request.get_json()
    url = data.get("url")
    print("Scanning URL:", url)

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Check if URL is already categorized in Redis (whitelist/blacklist)
    if redis_config.redis_client.sismember('whitelist', url):
        print(f"{url} found in whitelist")
        return jsonify({"url": url, "status": "safe", "source": "whitelist"}), 200
    if redis_config.redis_client.sismember('blacklist', url):
        print(f"{url} found in blacklist")
        return jsonify({"url": url, "status": "unsafe", "source": "blacklist"}), 200

    # Perform VirusTotal analysis using the check_virustotal function
    virus_total_risk = check_virustotal(url)  # Uses VirusTotal API
    print("VirusTotal Risk Level:", virus_total_risk)

   # Perform scraping and content analysis with the new dynamic scraper
is_risky, web_scrape_risk = scrape_and_has_form(url)
print("Web Scrape Risk Level:", web_scrape_risk)

    # Determine if the URL should be blacklisted or whitelisted
    if virus_total_risk in ["high", "medium"] or is_risky:
        add_to_blacklist(url, redis_config.redis_client)
        print(f"{url} added to blacklist")
        log_scan_result(url, {"status": "unsafe", "source": "scan"})  # Log scan result
        send_alert(f"Suspicious activity detected for URL: {url}")  # Send alert
        return jsonify({"url": url, "status": "unsafe", "source": "scan"}), 200
    else:
        add_to_whitelist(url, redis_config.redis_client)
        print(f"{url} added to whitelist")
        log_scan_result(url, {"status": "safe", "source": "scan"})  # Log scan result
        return jsonify({"url": url, "status": "safe", "source": "scan"}), 200

    # If URL is safe, add it to the whitelist
    add_to_whitelist(url, redis_config.redis_client)
    print(f"{url} added to whitelist")
    log_scan_result(url, {"status": "safe", "source": "scan"})  # Log scan result
    return jsonify({"url": url, "status": "safe", "source": "scan"}), 200


# Route to add a URL to the whitelist
@app.route('/add_to_whitelist', methods=['POST'])
def whitelist_url():
    """
    Adds a URL to the whitelist.
    """
    url = request.json.get('url')
    if add_to_whitelist(url, redis_config.redis_client):
        return jsonify({"message": "URL added to whitelist successfully!"}), 200
    return jsonify({"message": "URL is already in whitelist!"}), 400


# Route to add a URL to the blacklist
@app.route('/add_to_blacklist', methods=['POST'])
def blacklist_url():
    """
    Adds a URL to the blacklist.
    """
    url = request.json.get('url')
    if add_to_blacklist(url, redis_config.redis_client):
        return jsonify({"message": "URL added to blacklist successfully!"}), 200
    return jsonify({"message": "URL is already in blacklist!"}), 400


# Route to fetch all whitelisted URLs
@app.route('/get_whitelist', methods=['GET'])
def get_whitelist():
    """
    Fetches all whitelisted URLs.
    """
    urls = get_whitelisted(redis_config.redis_client)
    return jsonify({"whitelisted_urls": urls}), 200


# Route to fetch all blacklisted URLs
@app.route('/get_blacklist', methods=['GET'])
def get_blacklist():
    """
    Fetches all blacklisted URLs.
    """
    urls = get_blacklisted(redis_config.redis_client)
    return jsonify({"blacklisted_urls": urls}), 200


# This part checks the VirusTotal API to assess the threat level of a URL
def check_virustotal(url):
    """
    Check the URL using VirusTotal API and return the threat level.
    """
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    encoded_url = requests.utils.quote(url, safe='')  # Encoding URL to make it safe for the request
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


# This part scrapes the URL content for suspicious links or patterns
def scrape_url_content(url):
    """
    Perform web scraping to analyze URL content.
    """
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        # Perform analysis on `soup` content (you can enhance this)
        # Return a placeholder risk level based on scraping
        return "low"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/notifications')
def notifications():
    # Example response. You can replace this with real notifications data if needed.
    return jsonify({"message": "This is a test notification."})

# Entry point to run the app
if __name__ == '__main__':
    from main import run_app  # Import `run_app` from `main.py` as the entry point
    run_app(app)  # Use `run_app` to start the application
