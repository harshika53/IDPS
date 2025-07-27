from flask import Flask, request, jsonify, render_template, send_from_directory
import os
import csv
from dotenv import load_dotenv
from collections import deque

# Load environment variables
load_dotenv()

# Custom module imports
import redis_config
from urls import add_to_whitelist, add_to_blacklist, get_whitelisted, get_blacklisted
from passive_scanning import check_url_risk
from webscrapping import scrape_and_has_form
from scanner import advanced_url_analysis
from utility import log_scan_result

# Initialize Flask app
app = Flask(__name__)
app.config['STATIC_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

# In-memory store for the last 10 notifications
notifications_store = deque(maxlen=10)

def send_alert(message):
    notifications_store.appendleft(message)

# --- App Routes ---

@app.route('/')
def home():
    return render_template('new_dashboard.html')

@app.route('/download_csv/<path:filename>')
def download_csv(filename):
    try:
        return send_from_directory(app.config.get('STATIC_FOLDER'), filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "File not found."}), 404

@app.route('/get_notifications', methods=['GET'])
def get_notifications():
    return jsonify(list(notifications_store))

@app.route('/get_logs', methods=['GET'])
def get_activity_logs():
    log_file_path = os.path.join(app.config.get('STATIC_FOLDER'), 'admin_data.csv')
    logs = []
    try:
        with open(log_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                logs.append(row)
        return jsonify(list(reversed(logs)))
    except FileNotFoundError:
        return jsonify([])
    except Exception as e:
        print(f"Error reading log file: {e}")
        return jsonify({"error": "Could not read log file."}), 500

@app.route('/passive_scan', methods=['POST'])
def passive_scan():
    print("\n--- NEW SCAN INITIATED ---")
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data['url']
    print(f"[DEBUG] 1. Received URL: {url}")

    # Fix: Check cache with proper string encoding
    if redis_config.redis_client.sismember('whitelist', url):
        print(f"[DEBUG] URL found in whitelist: {url}")
        log_scan_result(url, {"status": "safe", "source": "whitelist"})
        return jsonify({"url": url, "status": "safe", "source": "whitelist"}), 200
        
    if redis_config.redis_client.sismember('blacklist', url):
        print(f"[DEBUG] URL found in blacklist: {url}")
        log_scan_result(url, {"status": "unsafe", "source": "blacklist"})
        return jsonify({"url": url, "status": "unsafe", "source": "blacklist"}), 200

    print(f"[DEBUG] URL not found in cache, proceeding with scan...")

    # Local pattern scan (from scanner.py)
    risk_score, reasons = advanced_url_analysis(url)
    print(f"[DEBUG] 2. Local Scan Risk Score: {risk_score}, Reasons: {reasons}")
    if risk_score >= 5:
        add_to_blacklist(url, redis_config.redis_client)
        log_scan_result(url, {"status": "unsafe", "source": "local_pattern_scan"})
        send_alert(f"High-risk pattern in URL: {url}")
        return jsonify({"url": url, "status": "unsafe", "source": "local_pattern_scan"}), 200

    # VirusTotal scan
    virus_total_risk = check_url_risk(url)
    print(f"[DEBUG] 3. VirusTotal Risk: '{virus_total_risk}'")

    # Web scraping scan
    is_risky, web_scrape_analysis = scrape_and_has_form(url)
    print(f"[DEBUG] 4. Web Scrape Result: is_risky={is_risky}, analysis='{web_scrape_analysis}'")

    # Final decision
    if virus_total_risk in ["high", "medium"] or is_risky:
        add_to_blacklist(url, redis_config.redis_client)
        send_alert(f"Threat detected and blocked: {url}")
        log_scan_result(url, {"status": "unsafe", "source": "scan"})
        return jsonify({"url": url, "status": "unsafe", "source": "scan"}), 200
    else:
        add_to_whitelist(url, redis_config.redis_client)
        log_scan_result(url, {"status": "safe", "source": "scan"})
        return jsonify({"url": url, "status": "safe", "source": "scan"}), 200

# Other routes for manual list management
@app.route('/add_to_whitelist', methods=['POST'])
def whitelist_url():
    url = request.json.get('url')
    if add_to_whitelist(url, redis_config.redis_client):
        send_alert(f"Manual action: {url} was whitelisted.")
        return jsonify({"message": "URL added to whitelist successfully!"}), 200
    return jsonify({"message": "URL is already in whitelist!"}), 400

@app.route('/add_to_blacklist', methods=['POST'])
def blacklist_url():
    url = request.json.get('url')
    if add_to_blacklist(url, redis_config.redis_client):
        send_alert(f"Manual action: {url} was blacklisted.")
        return jsonify({"message": "URL added to blacklist successfully!"}), 200
    return jsonify({"message": "URL is already in blacklist!"}), 400

@app.route('/get_whitelist', methods=['GET'])
def get_whitelist():
    urls = get_whitelisted(redis_config.redis_client)
    return jsonify({"whitelisted_urls": urls}), 200

@app.route('/get_blacklist', methods=['GET'])
def get_blacklist():
    urls = get_blacklisted(redis_config.redis_client)
    return jsonify({"blacklisted_urls": urls}), 200

if __name__ == '__main__':
    app.run(debug=True)
