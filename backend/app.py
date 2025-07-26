from flask import Flask, request, jsonify, render_template, send_from_directory
import os
from dotenv import load_dotenv
import csv

# Load environment variables from .env file
load_dotenv()

# Custom module imports
from urls import add_to_whitelist, add_to_blacklist, get_whitelisted, get_blacklisted
import redis_config as redis_config
from passive_scanning import check_url_risk
from webscrapping import scrape_and_has_form
from utility import send_alert, log_scan_result

# Initialize Flask app
app = Flask(__name__)
# Define the static folder path for file downloads
app.config['STATIC_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')


# --- App Routes ---

@app.route('/')
def home():
    """
    Serves the main HTML page.
    """
    return render_template('new_dashboard.html')
    
@app.route('/download_csv/<path:filename>')
def download_csv(filename):
    """
    Provides CSV files for download from the static directory.
    """
    static_folder = app.config.get('STATIC_FOLDER')
    try:
        # Securely send the requested file from the static folder
        return send_from_directory(static_folder, filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "File not found."}), 404    


@app.route('/passive_scan', methods=['POST'])
def passive_scan():
    """
    Scans a URL using VirusTotal and our dynamic web scraper, then classifies it.
    (This version includes detailed debugging print statements).
    """
    print("\n--- NEW SCAN INITIATED ---")
    data = request.get_json()
    if not data or 'url' not in data:
        print("[DEBUG] ERROR: No URL found in request.")
        return jsonify({"error": "URL is required"}), 400

    url = data['url']
    print(f"[DEBUG] 1. Received URL for scanning: {url}")

    # Check cache first
    if redis_config.redis_client.sismember('whitelist', url):
        print(f"[DEBUG] 2. Result: Found in whitelist (cache).")
        return jsonify({"url": url, "status": "safe", "source": "whitelist"}), 200
    if redis_config.redis_client.sismember('blacklist', url):
        print(f"[DEBUG] 2. Result: Found in blacklist (cache).")
        return jsonify({"url": url, "status": "unsafe", "source": "blacklist"}), 200

    # 1. Perform VirusTotal analysis
    print("[DEBUG] 3. Calling VirusTotal function (check_url_risk)...")
    virus_total_risk = check_url_risk(url)
    print(f"[DEBUG] 4. Received from VirusTotal: '{virus_total_risk}'")

    # 2. Perform dynamic content analysis
    print("[DEBUG] 5. Calling web scraping function (scrape_and_has_form)...")
    is_risky, web_scrape_analysis = scrape_and_has_form(url)
    print(f"[DEBUG] 6. Received from web scraper: is_risky={is_risky}, analysis='{web_scrape_analysis}'")

    # 3. Classify based on combined results
    print("[DEBUG] 7. Making final decision...")
    if virus_total_risk in ["high", "medium"] or is_risky:
        add_to_blacklist(url, redis_config.redis_client)
        print(f"[DEBUG] 8. FINAL DECISION: Unsafe. Added to blacklist.")
        log_scan_result(url, {"status": "unsafe", "source": "scan"})
        send_alert(f"Suspicious activity detected for URL: {url}")
        return jsonify({"url": url, "status": "unsafe", "source": "scan"}), 200
    else:
        add_to_whitelist(url, redis_config.redis_client)
        print(f"[DEBUG] 8. FINAL DECISION: Safe. Added to whitelist.")
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

@app.route('/get_logs', methods=['GET'])
def get_activity_logs():
    """
    Reads the admin_data.csv log file and returns its content.
    """
    log_file_path = os.path.join(app.config.get('STATIC_FOLDER'), 'admin_data.csv')
    logs = []
    try:
        # Open and read the CSV file
        with open(log_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
            # Use DictReader to make each row a dictionary
            reader = csv.DictReader(csvfile)
            for row in reader:
                logs.append(row)
        # Return the most recent logs first
        return jsonify(list(reversed(logs)))
    except FileNotFoundError:
        # If the file doesn't exist yet, return an empty list
        return jsonify([])
    except Exception as e:
        print(f"Error reading log file: {e}")
        return jsonify({"error": "Could not read log file."}), 500

@app.route('/notifications')
def notifications():
    # Placeholder for a real notification system
    return jsonify([{"message": "System is running normally."}])

# Entry point to run the app
if __name__ == '__main__':
    app.run(debug=True)