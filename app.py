from flask import Flask, request, jsonify, render_template, send_from_directory
import os
from dotenv import load_dotenv
from collections import deque

# Load environment variables
load_dotenv()

# Custom module imports
from urls import add_to_whitelist, add_to_blacklist, get_whitelisted, get_blacklisted
import redis_config as redis_config
from passive_scanning import check_url_risk
from webscrapping import scrape_and_has_form
from utility import log_scan_result  # We will handle alerts directly in app.py

# Initialize Flask app
app = Flask(__name__)
app.config['STATIC_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

# In-memory store for the last 10 notifications using a deque
# A deque is a list-like container with fast appends and pops from both ends.
notifications_store = deque(maxlen=10)

def send_alert(message):
    """Adds a new notification message to our in-memory store."""
    notifications_store.appendleft(message) # Add to the beginning

# --- App Routes ---

@app.route('/')
def home():
    """Serves the main HTML page."""
    return render_template('new_dashboard.html')

@app.route('/download_csv/<path:filename>')
def download_csv(filename):
    """Provides CSV files for download."""
    try:
        return send_from_directory(app.config.get('STATIC_FOLDER'), filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "File not found."}), 404

# --- THIS IS THE NEW NOTIFICATIONS ENDPOINT ---
@app.route('/get_notifications', methods=['GET'])
def get_notifications():
    """Returns the list of stored notifications."""
    return jsonify(list(notifications_store))


@app.route('/passive_scan', methods=['POST'])
def passive_scan():
    """Scans a URL and handles notifications."""
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data['url']
    
    # Check cache first
    if redis_config.redis_client.sismember('whitelist', url):
        return jsonify({"url": url, "status": "safe", "source": "whitelist"}), 200
    if redis_config.redis_client.sismember('blacklist', url):
        return jsonify({"url": url, "status": "unsafe", "source": "blacklist"}), 200

    # Perform scans
    virus_total_risk = check_url_risk(url)
    is_risky, web_scrape_analysis = scrape_and_has_form(url)

    # Classify and send alerts
    if virus_total_risk in ["high", "medium"] or is_risky:
        add_to_blacklist(url, redis_config.redis_client)
        log_scan_result(url, {"status": "unsafe", "source": "scan"})
        # --- Send an alert when a threat is found ---
        send_alert(f"Threat detected and blocked: {url}")
        return jsonify({"url": url, "status": "unsafe", "source": "scan"}), 200
    else:
        add_to_whitelist(url, redis_config.redis_client)
        log_scan_result(url, {"status": "safe", "source": "scan"})
        return jsonify({"url": url, "status": "safe", "source": "scan"}), 200


# --- Other routes remain the same ---
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
