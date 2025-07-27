from flask import Flask, request, jsonify, render_template, send_from_directory
import os
import csv
from dotenv import load_dotenv
from collections import deque
import traceback

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

# --- Debug Routes ---
@app.route('/debug_redis', methods=['GET'])
def debug_redis():
    """Debug Redis connection and cache contents"""
    try:
        # Test Redis connection
        redis_config.redis_client.ping()
        
        # Get cache contents
        whitelist = list(redis_config.redis_client.smembers('whitelist'))
        blacklist = list(redis_config.redis_client.smembers('blacklist'))
        
        return jsonify({
            "redis_status": "connected",
            "whitelist_count": len(whitelist),
            "blacklist_count": len(blacklist),
            "whitelist": whitelist,
            "blacklist": blacklist
        })
    except Exception as e:
        return jsonify({
            "redis_status": "failed",
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500

@app.route('/debug_modules', methods=['GET'])
def debug_modules():
    """Test if all modules are working"""
    results = {}
    
    # Test VirusTotal
    try:
        from passive_scanning import VIRUSTOTAL_API_KEY
        results["virustotal_key"] = "present" if VIRUSTOTAL_API_KEY else "missing"
    except Exception as e:
        results["virustotal_error"] = str(e)
    
    # Test web scraping
    try:
        from webscrapping import get_dynamic_page_content
        results["webscraping"] = "module_loaded"
    except Exception as e:
        results["webscraping_error"] = str(e)
    
    # Test scanner
    try:
        from scanner import advanced_url_analysis
        test_score, test_reasons = advanced_url_analysis("http://test.com")
        results["scanner"] = f"working (score: {test_score})"
    except Exception as e:
        results["scanner_error"] = str(e)
    
    return jsonify(results)

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
    print("\n" + "="*50)
    print("--- NEW SCAN INITIATED ---")
    print("="*50)
    
    try:
        data = request.get_json()
        print(f"[DEBUG] Raw request data: {data}")
        
        if not data or 'url' not in data:
            print("[DEBUG] ERROR: No URL provided in request")
            return jsonify({"error": "URL is required"}), 400

        url = data['url'].strip()
        print(f"[DEBUG] 1. Processing URL: '{url}'")

        # Test Redis connection first
        try:
            redis_config.redis_client.ping()
            print("[DEBUG] Redis connection: OK")
        except Exception as e:
            print(f"[DEBUG] Redis connection FAILED: {e}")
            return jsonify({"error": "Redis connection failed", "details": str(e)}), 500

        # Check whitelist
        print("[DEBUG] 2. Checking whitelist...")
        try:
            is_whitelisted = redis_config.redis_client.sismember('whitelist', url)
            print(f"[DEBUG] Whitelist check result: {is_whitelisted}")
            
            if is_whitelisted:
                print(f"[DEBUG] URL found in whitelist: {url}")
                log_scan_result(url, {"status": "safe", "source": "whitelist"})
                return jsonify({"url": url, "status": "safe", "source": "whitelist"}), 200
        except Exception as e:
            print(f"[DEBUG] Whitelist check FAILED: {e}")
            traceback.print_exc()

        # Check blacklist
        print("[DEBUG] 3. Checking blacklist...")
        try:
            is_blacklisted = redis_config.redis_client.sismember('blacklist', url)
            print(f"[DEBUG] Blacklist check result: {is_blacklisted}")
            
            if is_blacklisted:
                print(f"[DEBUG] URL found in blacklist: {url}")
                log_scan_result(url, {"status": "unsafe", "source": "blacklist"})
                return jsonify({"url": url, "status": "unsafe", "source": "blacklist"}), 200
        except Exception as e:
            print(f"[DEBUG] Blacklist check FAILED: {e}")
            traceback.print_exc()

        print("[DEBUG] 4. URL not in cache, proceeding with full scan...")

        # Local pattern scan
        print("[DEBUG] 5. Running local pattern scan...")
        try:
            risk_score, reasons = advanced_url_analysis(url)
            print(f"[DEBUG] Local scan - Risk Score: {risk_score}, Reasons: {reasons}")
            
            if risk_score >= 5:
                print("[DEBUG] High risk detected by local scan")
                add_to_blacklist(url, redis_config.redis_client)
                log_scan_result(url, {"status": "unsafe", "source": "local_pattern_scan"})
                send_alert(f"High-risk pattern in URL: {url}")
                return jsonify({"url": url, "status": "unsafe", "source": "local_pattern_scan"}), 200
        except Exception as e:
            print(f"[DEBUG] Local scan FAILED: {e}")
            traceback.print_exc()

        # VirusTotal scan
        print("[DEBUG] 6. Running VirusTotal scan...")
        try:
            virus_total_risk = check_url_risk(url)
            print(f"[DEBUG] VirusTotal result: '{virus_total_risk}'")
        except Exception as e:
            print(f"[DEBUG] VirusTotal scan FAILED: {e}")
            virus_total_risk = "error"
            traceback.print_exc()

        # Web scraping scan
        print("[DEBUG] 7. Running web scraping scan...")
        try:
            is_risky, web_scrape_analysis = scrape_and_has_form(url)
            print(f"[DEBUG] Web scrape result: is_risky={is_risky}, analysis='{web_scrape_analysis}'")
        except Exception as e:
            print(f"[DEBUG] Web scraping FAILED: {e}")
            is_risky = False
            web_scrape_analysis = f"Error: {str(e)}"
            traceback.print_exc()

        # Final decision
        print("[DEBUG] 8. Making final decision...")
        if virus_total_risk in ["high", "medium"] or is_risky:
            print("[DEBUG] DECISION: URL is UNSAFE")
            add_to_blacklist(url, redis_config.redis_client)
            send_alert(f"Threat detected and blocked: {url}")
            log_scan_result(url, {"status": "unsafe", "source": "scan"})
            return jsonify({"url": url, "status": "unsafe", "source": "scan"}), 200
        else:
            print("[DEBUG] DECISION: URL is SAFE")
            add_to_whitelist(url, redis_config.redis_client)
            log_scan_result(url, {"status": "safe", "source": "scan"})
            return jsonify({"url": url, "status": "safe", "source": "scan"}), 200

    except Exception as e:
        print(f"[DEBUG] CRITICAL ERROR in passive_scan: {e}")
        traceback.print_exc()
        return jsonify({
            "error": "Internal server error", 
            "details": str(e),
            "traceback": traceback.format_exc()
        }), 500

# Other routes for manual list management
@app.route('/add_to_whitelist', methods=['POST'])
def whitelist_url():
    url = request.json.get('url')
    print(f"[DEBUG] Manual whitelist add: {url}")
    if add_to_whitelist(url, redis_config.redis_client):
        send_alert(f"Manual action: {url} was whitelisted.")
        return jsonify({"message": "URL added to whitelist successfully!"}), 200
    return jsonify({"message": "URL is already in whitelist!"}), 400

@app.route('/add_to_blacklist', methods=['POST'])
def blacklist_url():
    url = request.json.get('url')
    print(f"[DEBUG] Manual blacklist add: {url}")
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
    print("Starting IDPS application...")
    print("Debug endpoints available:")
    print("  GET /debug_redis - Check Redis connection and cache")
    print("  GET /debug_modules - Test all modules")
    app.run(debug=True)