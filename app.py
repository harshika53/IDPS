from flask import Flask, request, jsonify, render_template, send_from_directory
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Custom module imports
from urls import add_to_whitelist, add_to_blacklist, get_whitelisted, get_blacklisted
import redis_config as redis_config
from passive_scanning import check_url_risk # Updated import
from webscrapping import scrape_and_has_form # Updated import
from utility import send_alert, log_scan_result

# Initialize Flask app
app = Flask(__name__)

# --- App Routes ---

@app.route('/')
def home():
    """
    Serves the main HTML page.
    """
    return render_template('demopg.html')

@app.route('/passive_scan', methods=['POST'])
def passive_scan():
    """
    Scans a URL using VirusTotal and our dynamic web scraper, then classifies it.
    """
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data['url']
    print(f"Scanning URL: {url}")

    # Check cache first
    if redis_config.redis_client.sismember('whitelist', url):
        print(f"{url} found in whitelist (cache)")
        return jsonify({"url": url, "status": "safe", "source": "whitelist"}), 200
    if redis_config.redis_client.sismember('blacklist', url):
        print(f"{url} found in blacklist (cache)")
        return jsonify({"url": url, "status": "unsafe", "source": "blacklist"}), 200

    # 1. Perform VirusTotal analysis
    virus_total_risk = check_url_risk(url)
    print(f"VirusTotal Risk Level: {virus_total_risk}")

    # 2. Perform dynamic content analysis
    is_risky, web_scrape_analysis = scrape_and_has_form(url)
    print(f"Web Scrape Analysis: {web_scrape_analysis}")

    # 3. Classify based on combined results
    if virus_total_risk in ["high", "medium"] or is_risky:
        add_to_blacklist(url, redis_config.redis_client)
        print(f"{url} added to blacklist")
        log_scan_result(url, {"status": "unsafe", "source": "scan"})
        send_alert(f"Suspicious activity detected for URL: {url}")
        return jsonify({"url": url, "status": "unsafe", "source": "scan"}), 200
    else:
        add_to_whitelist(url, redis_config.redis_client)
        print(f"{url} added to whitelist")
        log_scan_result(url, {"status": "safe", "source": "scan"})
        return jsonify({"url": url, "status": "safe", "source": "scan"}), 200

@app.route('/add_to_whitelist', methods=['POST'])
def whitelist_url():
    """
    Manually adds a URL to the whitelist.
    """
    url = request.json.get('url')
    if add_to_whitelist(url, redis_config.redis_client):
        return jsonify({"message": "URL added to whitelist successfully!"}), 200
    return jsonify({"message": "URL is already in whitelist!"}), 400

@app.route('/add_to_blacklist', methods=['POST'])
def blacklist_url():
    """
    Manually adds a URL to the blacklist.
    """
    url = request.json.get('url')
    if add_to_blacklist(url, redis_config.redis_client):
        return jsonify({"message": "URL added to blacklist successfully!"}), 200
    return jsonify({"message": "URL is already in blacklist!"}), 400

@app.route('/get_whitelist', methods=['GET'])
def get_whitelist():
    """
    Fetches all whitelisted URLs.
    """
    urls = get_whitelisted(redis_config.redis_client)
    return jsonify({"whitelisted_urls": urls}), 200

@app.route('/get_blacklist', methods=['GET'])
def get_blacklist():
    """
    Fetches all blacklisted URLs.
    """
    urls = get_blacklisted(redis_config.redis_client)
    return jsonify({"blacklisted_urls": urls}), 200

@app.route('/notifications')
def notifications():
    # Placeholder for a real notification system
    return jsonify([{"message": "System is running normally."}])

# Entry point to run the app
if __name__ == '__main__':
    app.run(debug=True)
