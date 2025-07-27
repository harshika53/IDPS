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

        # Normalize URL for consistent checking
        normalized_url = normalize_url(url)
        print(f"[DEBUG] 1.1. Normalized URL: '{normalized_url}'")

        # FORCE cache initialization
        redis_config.redis_client._initialize()
        
        # Check whitelist first (check both original and normalized)
        print("[DEBUG] 2. Checking whitelist...")
        is_whitelisted = (redis_config.redis_client.sismember('whitelist', url) or 
                         redis_config.redis_client.sismember('whitelist', normalized_url))
        print(f"[DEBUG] Whitelist check result: {is_whitelisted}")
        
        if is_whitelisted:
            print(f"[DEBUG] URL found in whitelist: {url}")
            log_scan_result(url, {"status": "safe", "source": "whitelist"})
            return jsonify({"url": url, "status": "safe", "source": "whitelist"}), 200

        # Check blacklist (check both original and normalized)
        print("[DEBUG] 3. Checking blacklist...")
        is_blacklisted = (redis_config.redis_client.sismember('blacklist', url) or 
                         redis_config.redis_client.sismember('blacklist', normalized_url))
        print(f"[DEBUG] Blacklist check result: {is_blacklisted}")
        
        if is_blacklisted:
            print(f"[DEBUG] URL found in blacklist: {url}")
            log_scan_result(url, {"status": "unsafe", "source": "blacklist"})
            return jsonify({"url": url, "status": "unsafe", "source": "blacklist"}), 200

        print("[DEBUG] 4. URL not in cache, proceeding with comprehensive scan...")

        # COMPREHENSIVE SCANNING APPROACH
        total_risk_score = 0
        all_reasons = []
        scan_methods_used = []

        # METHOD 1: Advanced URL Pattern Analysis
        print("[DEBUG] 5. Running advanced URL analysis...")
        try:
            pattern_risk, pattern_reasons = advanced_url_analysis(url)
            total_risk_score += pattern_risk
            all_reasons.extend(pattern_reasons)
            scan_methods_used.append(f"url_analysis(score:{pattern_risk})")
            print(f"[DEBUG] URL analysis - Risk: {pattern_risk}, Reasons: {pattern_reasons}")
        except Exception as e:
            print(f"[DEBUG] URL analysis failed: {e}")
            scan_methods_used.append("url_analysis:error")

        # METHOD 2: VirusTotal Check (IF AVAILABLE)
        print("[DEBUG] 6. Attempting VirusTotal check...")
        try:
            if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "5fa54f5b2c07367e5f6796db0a5938ff389b1b69449d6d8deaa5347142051727":
                virus_total_result = check_url_risk(url)
                print(f"[DEBUG] VirusTotal result: {virus_total_result}")
                
                if virus_total_result == "high":
                    total_risk_score += 8
                    all_reasons.append("VirusTotal: High risk detected")
                    scan_methods_used.append("virustotal:high_risk")
                elif virus_total_result == "medium":
                    total_risk_score += 4
                    all_reasons.append("VirusTotal: Medium risk detected")
                    scan_methods_used.append("virustotal:medium_risk")
                elif virus_total_result == "low":
                    scan_methods_used.append("virustotal:clean")
                else:
                    scan_methods_used.append("virustotal:error")
            else:
                print("[DEBUG] VirusTotal API key not configured, skipping...")
                scan_methods_used.append("virustotal:skipped")
                
        except Exception as e:
            print(f"[DEBUG] VirusTotal check failed: {e}")
            scan_methods_used.append("virustotal:error")

        # METHOD 3: Content and Form Analysis
        print("[DEBUG] 7. Attempting content analysis...")
        try:
            has_suspicious_forms, form_analysis = scrape_and_has_form(url)
            if has_suspicious_forms:
                total_risk_score += 5
                all_reasons.append(f"Suspicious forms: {form_analysis}")
                scan_methods_used.append("form_analysis:suspicious")
            else:
                scan_methods_used.append("form_analysis:clean")
            print(f"[DEBUG] Form analysis - Suspicious: {has_suspicious_forms}")
        except Exception as e:
            print(f"[DEBUG] Form analysis failed: {e}")
            scan_methods_used.append("form_analysis:error")

        # METHOD 4: Content Anomaly Detection
        print("[DEBUG] 8. Attempting content anomaly detection...")
        try:
            has_anomalies, anomaly_details = detect_content_anomalies(url)
            if has_anomalies:
                total_risk_score += 3
                all_reasons.append(f"Content anomalies: {anomaly_details}")
                scan_methods_used.append("content_anomalies:detected")
            else:
                scan_methods_used.append("content_anomalies:clean")
            print(f"[DEBUG] Content anomalies - Detected: {has_anomalies}")
        except Exception as e:
            print(f"[DEBUG] Content anomaly detection failed: {e}")
            scan_methods_used.append("content_anomalies:error")

        # METHOD 5: Enhanced HTTP Analysis
        print("[DEBUG] 9. Running enhanced HTTP analysis...")
        try:
            http_risk, http_reasons = perform_http_analysis(url)
            total_risk_score += http_risk
            all_reasons.extend(http_reasons)
            scan_methods_used.append(f"http_analysis(score:{http_risk})")
            print(f"[DEBUG] HTTP analysis - Risk: {http_risk}, Reasons: {http_reasons}")
        except Exception as e:
            print(f"[DEBUG] HTTP analysis failed: {e}")
            scan_methods_used.append("http_analysis:error")

        # DECISION MAKING WITH LOWER THRESHOLD
        print(f"[DEBUG] 10. Making final decision...")
        print(f"[DEBUG] Total risk score: {total_risk_score}")
        print(f"[DEBUG] All reasons: {all_reasons}")
        print(f"[DEBUG] Methods used: {scan_methods_used}")

        # LOWERED THRESHOLD: Now 2 instead of 3
        if total_risk_score >= 2:
            decision = "unsafe"
            print(f"[DEBUG] DECISION: URL is UNSAFE (score: {total_risk_score} >= 2)")
        else:
            decision = "safe"
            print(f"[DEBUG] DECISION: URL is SAFE (score: {total_risk_score} < 2)")

        # Update cache and logs
        if decision == "unsafe":
            add_to_blacklist(url, redis_config.redis_client)
            send_alert(f"Threat detected: {url} (Risk score: {total_risk_score})")
        else:
            add_to_whitelist(url, redis_config.redis_client)

        # Enhanced logging
        log_scan_result(url, {
            "status": decision,
            "source": "scan",
            "risk_score": total_risk_score,
            "reasons": all_reasons,
            "methods": scan_methods_used
        })

        # Return detailed result
        return jsonify({
            "url": url,
            "status": decision,
            "source": "scan",
            "risk_score": total_risk_score,
            "reasons": all_reasons[:5],  # Show top 5 reasons
            "methods_used": scan_methods_used,
            "threshold_used": 2
        }), 200

    except Exception as e:
        print(f"[DEBUG] CRITICAL ERROR in passive_scan: {e}")
        traceback.print_exc()
        
        # Enhanced fallback with better pattern matching
        try:
            url = data.get('url', '').strip() if data else 'unknown'
            fallback_risk = calculate_fallback_risk(url)
            
            if fallback_risk >= 2:
                fallback_decision = "unsafe"
            else:
                fallback_decision = "safe"
            
            print(f"[DEBUG] FALLBACK DECISION: {fallback_decision} (risk: {fallback_risk})")
            
            return jsonify({
                "url": url,
                "status": fallback_decision,
                "source": "fallback",
                "risk_score": fallback_risk,
                "warning": "Primary scan failed, using enhanced fallback analysis",
                "error": str(e)
            }), 200
            
        except:
            return jsonify({
                "error": "Complete scan failure",
                "details": str(e)
            }), 500

def normalize_url(url):
    """Normalize URL for consistent checking"""
    import re
    from urllib.parse import urlparse
    
    # Remove common prefixes and normalize
    url = url.strip()
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Parse and reconstruct
    try:
        parsed = urlparse(url)
        # Normalize domain to lowercase
        normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized
    except:
        return url

def calculate_fallback_risk(url):
    """Enhanced fallback risk calculation"""
    risk_score = 0
    url_lower = url.lower()
    
    # High-risk patterns
    high_risk_patterns = [
        'mp3raid', 'torrent', 'crack', 'keygen', 'warez', 'pirate',
        'bittorrent', 'allmusic', 'mp3', 'download', 'free-', 'hack'
    ]
    
    for pattern in high_risk_patterns:
        if pattern in url_lower:
            risk_score += 3
            break
    
    # Medium-risk patterns
    medium_risk_patterns = [
        'login', 'signin', 'admin', 'password', 'secure', 'verify',
        'account', 'banking', 'paypal', 'update', 'suspended'
    ]
    
    for pattern in medium_risk_patterns:
        if pattern in url_lower:
            risk_score += 2
            break
    
    # File extensions
    if any(url_lower.endswith(ext) for ext in ['.exe', '.zip', '.rar', '.scr', '.bat']):
        risk_score += 4
    
    # Non-HTTPS
    if url.startswith('http://'):
        risk_score += 1
    
    # Very long URLs
    if len(url) > 150:
        risk_score += 1
    
    return risk_score

def perform_http_analysis(url):
    """Enhanced HTTP analysis with better detection"""
    risk_score = 0
    reasons = []
    
    try:
        import requests
        from urllib.parse import urlparse
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        
        # Check for suspicious redirects
        if len(response.history) > 2:
            risk_score += 2
            reasons.append(f"Multiple redirects ({len(response.history)})")
        
        # Check final URL vs original
        if response.url != url:
            parsed_original = urlparse(url)
            parsed_final = urlparse(response.url)
            if parsed_original.netloc.lower() != parsed_final.netloc.lower():
                risk_score += 3
                reasons.append("Suspicious domain redirect")
        
        # Check response headers
        headers_check = response.headers
        
        # Missing security headers
        security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options']
        missing_count = sum(1 for h in security_headers if h not in headers_check)
        if missing_count >= 2:
            risk_score += 1
            reasons.append("Missing security headers")
        
        # Check content type
        content_type = headers_check.get('Content-Type', '').lower()
        if 'application/octet-stream' in content_type:
            risk_score += 3
            reasons.append("Binary download detected")
        
        # Check server header for suspicious values
        server = headers_check.get('Server', '').lower()
        suspicious_servers = ['apache/1.', 'nginx/0.', 'iis/6.']
        if any(sus in server for sus in suspicious_servers):
            risk_score += 1
            reasons.append("Outdated server software")
            
    except requests.exceptions.Timeout:
        risk_score += 2
        reasons.append("Request timeout (suspicious)")
    except requests.exceptions.ConnectionError:
        risk_score += 1
        reasons.append("Connection failed")
    except requests.exceptions.SSLError:
        risk_score += 3
        reasons.append("SSL/TLS certificate error")
    except Exception as e:
        reasons.append(f"HTTP analysis error: {str(e)}")
    
    return risk_score, reasons

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
            "csv_files_exist": csv_exists
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 500

# Test endpoint for debugging
@app.route('/test_scan_detailed', methods=['POST'])
def test_scan_detailed():
    """Test endpoint that shows detailed analysis without cache"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URL is required"}), 400
            
        url = data['url'].strip()
        print(f"[TEST-SCAN] Testing URL: {url}")
        
        # Skip cache completely
        results = {"url": url, "detailed_analysis": {}}
        
        # Test each component
        try:
            pattern_risk, pattern_reasons = advanced_url_analysis(url)
            results["detailed_analysis"]["url_patterns"] = {
                "risk_score": pattern_risk,
                "reasons": pattern_reasons
            }
        except Exception as e:
            results["detailed_analysis"]["url_patterns"] = {"error": str(e)}
        
        try:
            fallback_risk = calculate_fallback_risk(url)
            results["detailed_analysis"]["fallback_analysis"] = {
                "risk_score": fallback_risk
            }
        except Exception as e:
            results["detailed_analysis"]["fallback_analysis"] = {"error": str(e)}
        
        return jsonify(results), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting Enhanced IDPS application...")
    print("✅ Lowered detection threshold to 2 points")
    print("🔍 Enhanced pattern matching and analysis")
    print("📊 Debug endpoint: GET /debug_redis")
    print("🧪 Test endpoint: POST /test_scan_detailed")
    
    # Force early initialization
    try:
        redis_config.redis_client._initialize()
        print("✅ Cache pre-initialized successfully")
    except Exception as e:
        print(f"⚠️  Cache pre-initialization failed: {e}")
    
    app.run(debug=True)