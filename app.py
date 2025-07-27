from flask import Flask, request, jsonify, render_template, send_from_directory
import os
import csv
from dotenv import load_dotenv
from collections import deque
import traceback

# Load environment variables
load_dotenv()

# Get VirusTotal API key from environment
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Custom module imports
import redis_config
from urls import add_to_whitelist, add_to_blacklist, get_whitelisted, get_blacklisted
from passive_scanning import check_url_risk
from webscrapping import scrape_and_has_form
from scanner import advanced_url_analysis, detect_content_anomalies
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
    """Enhanced debug Redis connection and cache contents"""
    try:
        # Force initialization
        redis_config.redis_client._initialize()
        
        # Test Redis connection
        redis_config.redis_client.ping()
        
        # Get cache contents
        whitelist = redis_config.redis_client.smembers('whitelist')
        blacklist = redis_config.redis_client.smembers('blacklist')
        
        return jsonify({
            "redis_status": "connected",
            "cache_initialized": redis_config.redis_client.initialized,
            "whitelist_count": len(whitelist),
            "blacklist_count": len(blacklist),
            "whitelist": whitelist[:10],  # Show first 10
            "blacklist": blacklist[:10],   # Show first 10
            "full_whitelist": whitelist,  # Show all for debugging
            "full_blacklist": blacklist   # Show all for debugging
        })
    except Exception as e:
        return jsonify({
            "redis_status": "failed",
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500

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

        # FORCE cache initialization
        redis_config.redis_client._initialize()
        
        # Check whitelist first
        print("[DEBUG] 2. Checking whitelist...")
        is_whitelisted = redis_config.redis_client.sismember('whitelist', url)
        print(f"[DEBUG] Whitelist check result: {is_whitelisted}")
        
        if is_whitelisted:
            print(f"[DEBUG] URL found in whitelist: {url}")
            log_scan_result(url, {"status": "safe", "source": "whitelist"})
            return jsonify({"url": url, "status": "safe", "source": "whitelist"}), 200

        # Check blacklist
        print("[DEBUG] 3. Checking blacklist...")
        is_blacklisted = redis_config.redis_client.sismember('blacklist', url)
        print(f"[DEBUG] Blacklist check result: {is_blacklisted}")
        
        if is_blacklisted:
            print(f"[DEBUG] URL found in blacklist: {url}")
            log_scan_result(url, {"status": "unsafe", "source": "blacklist"})
            return jsonify({"url": url, "status": "unsafe", "source": "blacklist"}), 200

        print("[DEBUG] 4. URL not in cache, proceeding with scan...")

        # SIMPLIFIED SCANNING APPROACH
        risk_score = 0
        reasons = []
        scan_methods_tried = []

        # METHOD 1: Basic Pattern Analysis (ALWAYS WORKS)
        print("[DEBUG] 5. Running basic pattern analysis...")
        try:
            suspicious_patterns = [
                'login', 'signin', 'admin', 'password', 'secure', 'verify', 
                'account', 'banking', 'paypal', 'update', 'suspended'
            ]
            
            malicious_extensions = ['.exe', '.zip', '.rar', '.scr', '.bat', '.cmd', '.vbs']
            
            url_lower = url.lower()
            
            # Check for suspicious keywords
            pattern_matches = [p for p in suspicious_patterns if p in url_lower]
            if pattern_matches:
                risk_score += len(pattern_matches) * 2
                reasons.append(f"Suspicious keywords: {', '.join(pattern_matches)}")
                print(f"[DEBUG] Found suspicious patterns: {pattern_matches}")
            
            # Check for malicious file extensions
            ext_matches = [ext for ext in malicious_extensions if url_lower.endswith(ext)]
            if ext_matches:
                risk_score += 5
                reasons.append(f"Dangerous file extension: {', '.join(ext_matches)}")
                print(f"[DEBUG] Found dangerous extensions: {ext_matches}")
            
            # Check for IP addresses instead of domains
            import re
            ip_pattern = r'https?://(?:\d{1,3}\.){3}\d{1,3}'
            if re.search(ip_pattern, url):
                risk_score += 3
                reasons.append("Uses IP address instead of domain")
                print("[DEBUG] URL uses IP address")
            
            # Check for very long URLs (often used in phishing)
            if len(url) > 100:
                risk_score += 1
                reasons.append("Unusually long URL")
                print(f"[DEBUG] Long URL detected: {len(url)} characters")
            
            # Check for non-HTTPS
            if url.startswith('http://'):
                risk_score += 1
                reasons.append("Uses insecure HTTP protocol")
                print("[DEBUG] Non-HTTPS URL")
            
            scan_methods_tried.append(f"pattern_analysis(score:{risk_score})")
            print(f"[DEBUG] Basic pattern analysis complete. Risk score: {risk_score}")
            
        except Exception as e:
            print(f"[DEBUG] Pattern analysis failed: {e}")
            reasons.append(f"Pattern analysis error: {str(e)}")

        # METHOD 2: VirusTotal Check (IF AVAILABLE)
        virus_total_result = "unknown"
        print("[DEBUG] 6. Attempting VirusTotal check...")
        try:
            # Only try VirusTotal if we have an API key
            if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "5fa54f5b2c07367e5f6796db0a5938ff389b1b69449d6d8deaa5347142051727":
                virus_total_result = check_url_risk(url)
                print(f"[DEBUG] VirusTotal result: {virus_total_result}")
                
                if virus_total_result == "high":
                    risk_score += 5
                    reasons.append("VirusTotal flagged as high risk")
                    scan_methods_tried.append("virustotal:high")
                elif virus_total_result == "medium":
                    risk_score += 2
                    reasons.append("VirusTotal flagged as medium risk")
                    scan_methods_tried.append("virustotal:medium")
                elif virus_total_result == "low":
                    scan_methods_tried.append("virustotal:clean")
                else:
                    scan_methods_tried.append("virustotal:error")
            else:
                print("[DEBUG] VirusTotal API key not configured, skipping...")
                virus_total_result = "skipped"
                scan_methods_tried.append("virustotal:skipped")
                
        except Exception as e:
            print(f"[DEBUG] VirusTotal check failed: {e}")
            virus_total_result = "error"
            scan_methods_tried.append("virustotal:error")

        # METHOD 3: Simple HTTP Request Check
        print("[DEBUG] 7. Attempting basic HTTP check...")
        try:
            import requests
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
            print(f"[DEBUG] HTTP response status: {response.status_code}")
            
            # Check for suspicious redirects
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if location.lower() != url.lower():
                    risk_score += 1
                    reasons.append(f"Suspicious redirect to: {location[:50]}...")
                    print(f"[DEBUG] Redirect detected to: {location}")
            
            # Check response headers for security indicators
            security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options']
            missing_headers = [h for h in security_headers if h not in response.headers]
            if len(missing_headers) > 2:
                risk_score += 1
                reasons.append("Missing security headers")
                print(f"[DEBUG] Missing security headers: {missing_headers}")
            
            scan_methods_tried.append("http_check:success")
            
        except requests.exceptions.Timeout:
            print("[DEBUG] HTTP request timed out")
            reasons.append("Website timeout (suspicious)")
            risk_score += 1
            scan_methods_tried.append("http_check:timeout")
        except requests.exceptions.ConnectionError:
            print("[DEBUG] HTTP connection failed")
            reasons.append("Connection failed (site may be down)")
            risk_score += 2
            scan_methods_tried.append("http_check:connection_error")
        except Exception as e:
            print(f"[DEBUG] HTTP check failed: {e}")
            scan_methods_tried.append("http_check:error")

        # DECISION MAKING (SIMPLIFIED LOGIC)
        print(f"[DEBUG] 8. Making decision...")
        print(f"[DEBUG] Total risk score: {risk_score}")
        print(f"[DEBUG] Reasons: {reasons}")
        print(f"[DEBUG] Methods tried: {scan_methods_tried}")

        # Simple decision threshold
        if risk_score >= 3:
            decision = "unsafe"
            print("[DEBUG] DECISION: URL is UNSAFE")
        else:
            decision = "safe"
            print("[DEBUG] DECISION: URL is SAFE")

        # Update cache and logs
        if decision == "unsafe":
            add_to_blacklist(url, redis_config.redis_client)
            send_alert(f"Threat detected: {url} (Risk score: {risk_score})")
        else:
            add_to_whitelist(url, redis_config.redis_client)

        # Log the result
        log_scan_result(url, {
            "status": decision,
            "source": "scan",
            "risk_score": risk_score,
            "reasons": reasons,
            "methods": scan_methods_tried
        })

        # Return result
        return jsonify({
            "url": url,
            "status": decision,
            "source": "scan",
            "risk_score": risk_score,
            "reasons": reasons[:3],  # Limit reasons shown
            "methods_used": scan_methods_tried
        }), 200

    except Exception as e:
        print(f"[DEBUG] CRITICAL ERROR in passive_scan: {e}")
        traceback.print_exc()
        
        # FALLBACK: If everything fails, make a basic decision
        try:
            url = data.get('url', '').strip() if data else 'unknown'
            
            # Emergency fallback decision
            if any(word in url.lower() for word in ['login', 'admin', 'password', 'secure']):
                fallback_decision = "unsafe"
            else:
                fallback_decision = "safe"
            
            print(f"[DEBUG] FALLBACK DECISION: {fallback_decision}")
            
            return jsonify({
                "url": url,
                "status": fallback_decision,
                "source": "fallback",
                "warning": "Scan failed, using basic pattern matching",
                "error": str(e)
            }), 200
            
        except:
            return jsonify({
                "error": "Complete scan failure",
                "details": str(e)
            }), 500
    
# Other routes for manual list management
@app.route('/add_to_whitelist', methods=['POST'])
def whitelist_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URL is required"}), 400
            
        url = data['url'].strip()
        print(f"[DEBUG] Manual whitelist add: {url}")
        
        # Force cache initialization
        redis_config.redis_client._initialize()
        
        if add_to_whitelist(url, redis_config.redis_client):
            send_alert(f"Manual action: {url} was whitelisted.")
            log_scan_result(url, {"status": "safe", "source": "manual_whitelist"})
            return jsonify({"message": "URL added to whitelist successfully!"}), 200
        return jsonify({"message": "URL is already in whitelist!"}), 400
    except Exception as e:
        print(f"[DEBUG] Error in whitelist_url: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/add_to_blacklist', methods=['POST'])
def blacklist_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URL is required"}), 400
            
        url = data['url'].strip()
        print(f"[DEBUG] Manual blacklist add: {url}")
        
        # Force cache initialization
        redis_config.redis_client._initialize()
        
        if add_to_blacklist(url, redis_config.redis_client):
            send_alert(f"Manual action: {url} was blacklisted.")
            log_scan_result(url, {"status": "unsafe", "source": "manual_blacklist"})
            return jsonify({"message": "URL added to blacklist successfully!"}), 200
        return jsonify({"message": "URL is already in blacklist!"}), 200
    except Exception as e:
        print(f"[DEBUG] Error in blacklist_url: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/get_whitelist', methods=['GET'])
def get_whitelist():
    try:
        # Force cache initialization
        redis_config.redis_client._initialize()
        urls = get_whitelisted(redis_config.redis_client)
        return jsonify({"whitelisted_urls": urls}), 200
    except Exception as e:
        print(f"[DEBUG] Error in get_whitelist: {e}")
        return jsonify({"error": "Failed to fetch whitelist"}), 500

@app.route('/get_blacklist', methods=['GET'])
def get_blacklist():
    try:
        # Force cache initialization
        redis_config.redis_client._initialize()
        urls = get_blacklisted(redis_config.redis_client)
        return jsonify({"blacklisted_urls": urls}), 200
    except Exception as e:
        print(f"[DEBUG] Error in get_blacklist: {e}")
        return jsonify({"error": "Failed to fetch blacklist"}), 500

# Additional utility routes
@app.route('/clear_cache', methods=['POST'])
def clear_cache():
    """Clear all cache - useful for testing"""
    try:
        redis_config.clear_all_cache()
        send_alert("Cache cleared by admin")
        return jsonify({"message": "Cache cleared successfully"}), 200
    except Exception as e:
        print(f"[DEBUG] Error clearing cache: {e}")
        return jsonify({"error": "Failed to clear cache"}), 500

@app.route('/reinitialize_cache', methods=['POST'])
def reinitialize_cache():
    """Force reinitialize cache from CSV files"""
    try:
        redis_config.redis_client.initialized = False
        redis_config.redis_client._initialize()
        send_alert("Cache reinitialized from CSV files")
        return jsonify({"message": "Cache reinitialized successfully"}), 200
    except Exception as e:
        print(f"[DEBUG] Error reinitializing cache: {e}")
        return jsonify({"error": "Failed to reinitialize cache"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check cache
        redis_config.redis_client.ping()
        
        # Check if CSV files exist
        admin_file = os.path.join(app.config.get('STATIC_FOLDER'), 'admin_data.csv')
        csv_exists = os.path.exists(admin_file)
        
        return jsonify({
            "status": "healthy",
            "cache_initialized": redis_config.redis_client.initialized,
            "csv_files_exist": csv_exists,
            "timestamp": traceback.format_exc()
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 500
    # Add these routes to your existing app.py file

@app.route('/sync_csv_files', methods=['POST'])
def sync_csv_files():
    """
    Manual CSV synchronization endpoint
    Useful for testing or fixing inconsistencies
    """
    try:
        from utility import sync_all_csv_files
        sync_all_csv_files()
        send_alert("CSV files synchronized manually")
        return jsonify({"message": "CSV files synchronized successfully"}), 200
    except Exception as e:
        print(f"[DEBUG] Error syncing CSV files: {e}")
        return jsonify({"error": "Failed to synchronize CSV files"}), 500

@app.route('/csv_status', methods=['GET'])
def csv_status():
    """
    Check the status of all CSV files
    """
    try:
        import csv
        
        files_status = {}
        csv_files = ['admin_data.csv', 'whitelist.csv', 'blacklist.csv']
        
        for filename in csv_files:
            file_path = os.path.join(app.config.get('STATIC_FOLDER'), filename)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
                        reader = csv.DictReader(csvfile)
                        count = sum(1 for row in reader)
                        files_status[filename] = {
                            "exists": True,
                            "count": count,
                            "last_modified": os.path.getmtime(file_path)
                        }
                except Exception as e:
                    files_status[filename] = {
                        "exists": True,
                        "error": str(e)
                    }
            else:
                files_status[filename] = {"exists": False}
        
        return jsonify({
            "status": "success",
            "files": files_status
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

@app.route('/test_csv_update', methods=['POST'])
def test_csv_update():
    """
    Test endpoint to verify CSV updating functionality
    """
    try:
        data = request.get_json()
        test_url = data.get('url', 'https://test-example.com')
        test_status = data.get('status', 'safe')  # 'safe' or 'unsafe'
        
        # Test the CSV update functionality
        from utility import update_csv_files
        update_csv_files(test_url, test_status, 'test')
        
        return jsonify({
            "message": f"Test completed - {test_url} marked as {test_status}",
            "url": test_url,
            "status": test_status
        }), 200
        
    except Exception as e:
        print(f"[DEBUG] Error in test_csv_update: {e}")
        return jsonify({"error": "Test failed"}), 500
    
    # Add these debug endpoints to your app.py

@app.route('/debug_scan_components', methods=['POST'])
def debug_scan_components():
    """
    Test individual scan components separately
    """
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URL is required"}), 400
            
        url = data['url'].strip()
        results = {"url": url, "components": {}}
        
        # Test 1: Local pattern analysis
        try:
            from scanner import advanced_url_analysis
            risk_score, reasons = advanced_url_analysis(url)
            results["components"]["local_analysis"] = {
                "status": "success",
                "risk_score": risk_score,
                "reasons": reasons
            }
        except Exception as e:
            results["components"]["local_analysis"] = {
                "status": "failed",
                "error": str(e)
            }
        
        # Test 2: VirusTotal
        try:
            from passive_scanning import check_url_risk
            vt_result = check_url_risk(url)
            results["components"]["virustotal"] = {
                "status": "success",
                "result": vt_result
            }
        except Exception as e:
            results["components"]["virustotal"] = {
                "status": "failed",
                "error": str(e)
            }
        
        # Test 3: Content analysis (basic test)
        try:
            import requests
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            results["components"]["basic_fetch"] = {
                "status": "success",
                "status_code": response.status_code,
                "content_length": len(response.text)
            }
        except Exception as e:
            results["components"]["basic_fetch"] = {
                "status": "failed",
                "error": str(e)
            }
            
        return jsonify(results), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/simple_scan', methods=['POST'])
def simple_scan():
    """
    Simplified scan that bypasses cache and shows what happens
    """
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URL is required"}), 400
            
        url = data['url'].strip()
        print(f"[SIMPLE-SCAN] Testing URL: {url}")
        
        # Skip cache checks, go straight to scanning
        results = {
            "url": url,
            "cache_bypassed": True,
            "scan_results": {}
        }
        
        # Basic URL pattern check
        suspicious_patterns = ['login', 'signin', 'admin', 'secure', 'verify']
        pattern_matches = [p for p in suspicious_patterns if p in url.lower()]
        
        if pattern_matches:
            results["scan_results"]["pattern_analysis"] = {
                "risk": "medium",
                "matches": pattern_matches
            }
            decision = "unsafe"
        else:
            results["scan_results"]["pattern_analysis"] = {
                "risk": "low",
                "matches": []
            }
            decision = "safe"
        
        results["final_decision"] = decision
        results["reasoning"] = f"Based on pattern analysis: {decision}"
        
        return jsonify(results), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/test_imports', methods=['GET'])
def test_imports():
    """
    Test if all required modules can be imported
    """
    import_results = {}
    
    modules_to_test = [
        ('redis_config', 'redis_config'),
        ('scanner.advanced_url_analysis', 'scanner'),
        ('passive_scanning.check_url_risk', 'passive_scanning'),
        ('webscrapping.scrape_and_has_form', 'webscrapping'),
        ('urls.add_to_whitelist', 'urls'),
        ('utility.log_scan_result', 'utility')
    ]
    
    for import_path, module_name in modules_to_test:
        try:
            if '.' in import_path:
                module, function = import_path.split('.', 1)
                exec(f"from {module} import {function}")
            else:
                exec(f"import {import_path}")
            import_results[module_name] = "✅ Success"
        except Exception as e:
            import_results[module_name] = f"❌ Failed: {str(e)}"
    
    return jsonify({
        "import_test_results": import_results,
        "summary": "All imports successful" if all("Success" in result for result in import_results.values()) else "Some imports failed"
    }), 200

# Add this endpoint to your app.py

@app.route('/reload_cache_from_csv', methods=['POST'])
def reload_cache_from_csv():
    """Force reload cache from CSV files - prioritizes individual CSV files"""
    try:
        redis_config.redis_client.force_reload_from_csv()
        send_alert("Cache reloaded from CSV files")
        
        # Get the updated counts
        whitelist_count = len(redis_config.redis_client.smembers('whitelist'))
        blacklist_count = len(redis_config.redis_client.smembers('blacklist'))
        
        return jsonify({
            "message": "Cache reloaded successfully from CSV files",
            "whitelist_count": whitelist_count,
            "blacklist_count": blacklist_count,
            "source": "individual_csv_files"
        }), 200
    except Exception as e:
        print(f"[DEBUG] Error reloading cache from CSV: {e}")
        return jsonify({"error": "Failed to reload cache from CSV files"}), 500

@app.route('/compare_cache_vs_csv', methods=['GET'])
def compare_cache_vs_csv():
    """Compare what's in cache vs what's in CSV files"""
    try:
        import csv
        
        # Get current cache contents
        cache_whitelist = set(redis_config.redis_client.smembers('whitelist'))
        cache_blacklist = set(redis_config.redis_client.smembers('blacklist'))
        
        # Read CSV files
        csv_whitelist = set()
        csv_blacklist = set()
        
        # Read whitelist.csv
        whitelist_file = os.path.join(app.config.get('STATIC_FOLDER'), 'whitelist.csv')
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    csv_whitelist.add(row['url'].strip())
        
        # Read blacklist.csv
        blacklist_file = os.path.join(app.config.get('STATIC_FOLDER'), 'blacklist.csv')
        if os.path.exists(blacklist_file):
            with open(blacklist_file, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    csv_blacklist.add(row['url'].strip())
        
        # Compare
        return jsonify({
            "cache": {
                "whitelist_count": len(cache_whitelist),
                "blacklist_count": len(cache_blacklist),
                "whitelist_sample": list(cache_whitelist)[:5],
                "blacklist_sample": list(cache_blacklist)[:5]
            },
            "csv_files": {
                "whitelist_count": len(csv_whitelist),
                "blacklist_count": len(csv_blacklist),
                "whitelist_sample": list(csv_whitelist)[:5],
                "blacklist_sample": list(csv_blacklist)[:5]
            },
            "differences": {
                "whitelist_in_cache_not_csv": list(cache_whitelist - csv_whitelist),
                "whitelist_in_csv_not_cache": list(csv_whitelist - cache_whitelist),
                "blacklist_in_cache_not_csv": list(cache_blacklist - csv_blacklist),
                "blacklist_in_csv_not_cache": list(csv_blacklist - cache_blacklist)
            }
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    # Add this test endpoint to your app.py

@app.route('/test_scan_simple', methods=['POST'])
def test_scan_simple():
    """
    Ultra-simple scan test that doesn't depend on external services
    """
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URL is required"}), 400
            
        url = data['url'].strip()
        print(f"[SIMPLE-SCAN] Testing URL: {url}")
        
        # Skip cache entirely for testing
        risk_score = 0
        reasons = []
        
        # Basic checks that always work
        url_lower = url.lower()
        
        # Check 1: Suspicious keywords
        bad_words = ['login', 'admin', 'password', 'secure', 'banking', 'paypal']
        found_words = [word for word in bad_words if word in url_lower]
        if found_words:
            risk_score += len(found_words) * 2
            reasons.append(f"Suspicious words: {', '.join(found_words)}")
        
        # Check 2: File extensions
        if any(url_lower.endswith(ext) for ext in ['.exe', '.zip', '.scr', '.bat']):
            risk_score += 5
            reasons.append("Dangerous file extension")
        
        # Check 3: Protocol
        if url.startswith('http://'):
            risk_score += 1
            reasons.append("Insecure HTTP")
        
        # Check 4: Length
        if len(url) > 100:
            risk_score += 1
            reasons.append("Very long URL")
        
        # Decision
        if risk_score >= 3:
            status = "unsafe"
        else:
            status = "safe"
        
        print(f"[SIMPLE-SCAN] Result: {status} (score: {risk_score})")
        
        return jsonify({
            "url": url,
            "status": status,
            "risk_score": risk_score,
            "reasons": reasons,
            "test_mode": True
        }), 200
        
    except Exception as e:
        print(f"[SIMPLE-SCAN] Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/scan_debug_info', methods=['GET'])
def scan_debug_info():
    """
    Show debug information about the scanning setup
    """
    try:
        debug_info = {
            "virustotal_api_configured": bool(VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "5fa54f5b2c07367e5f6796db0a5938ff389b1b69449d6d8deaa5347142051727"),
            "cache_initialized": redis_config.redis_client.initialized,
            "required_functions_available": {}
        }
        
        # Test if required functions are available
        functions_to_test = [
            ("check_url_risk", "passive_scanning"),
            ("add_to_whitelist", "urls"),
            ("add_to_blacklist", "urls"),
            ("log_scan_result", "utility"),
            ("send_alert", "app")
        ]
        
        for func_name, module_name in functions_to_test:
            try:
                if module_name == "app":
                    # Function is in current module
                    func_exists = func_name in globals()
                else:
                    # Import and check
                    if module_name == "passive_scanning":
                        from passive_scanning import check_url_risk
                        func_exists = True
                    elif module_name == "urls":
                        from urls import add_to_whitelist, add_to_blacklist
                        func_exists = True
                    elif module_name == "utility":
                        from utility import log_scan_result
                        func_exists = True
                    else:
                        func_exists = False
                        
                debug_info["required_functions_available"][f"{module_name}.{func_name}"] = "✅ Available"
            except Exception as e:
                debug_info["required_functions_available"][f"{module_name}.{func_name}"] = f"❌ Error: {str(e)}"
        
        # Test basic Python modules
        modules_to_test = ["requests", "re", "json", "csv", "os"]
        debug_info["python_modules"] = {}
        
        for module in modules_to_test:
            try:
                __import__(module)
                debug_info["python_modules"][module] = "✅ Available"
            except ImportError as e:
                debug_info["python_modules"][module] = f"❌ Missing: {str(e)}"
        
        return jsonify(debug_info), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting IDPS application...")
    print("✅ Cache will auto-initialize on startup")
    print("🔍 Enhanced scanning with lower detection thresholds")
    print("📊 Debug endpoint: GET /debug_redis")
    print("🔧 Additional endpoints:")
    print("   - POST /clear_cache (clear all cache)")
    print("   - POST /reinitialize_cache (reload from CSV)")
    print("   - GET /health (health check)")
    
    # Force early initialization
    try:
        redis_config.redis_client._initialize()
        print("✅ Cache pre-initialized successfully")
    except Exception as e:
        print(f"⚠️  Cache pre-initialization failed: {e}")
    
    app.run(debug=True)