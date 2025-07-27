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

        print("[DEBUG] 4. URL not in cache, proceeding with full scan...")

        # Initialize scan results
        total_risk_score = 0
        all_reasons = []
        scan_sources = []
        scan_successful = False

        # 1. Local pattern scan (LOWERED THRESHOLD)
        print("[DEBUG] 5. Running local pattern scan...")
        try:
            risk_score, reasons = advanced_url_analysis(url)
            total_risk_score += risk_score
            all_reasons.extend(reasons)
            print(f"[DEBUG] Local scan - Risk Score: {risk_score}")
            scan_successful = True
            
            if risk_score >= 3:  # LOWERED from 5 to 3
                print("[DEBUG] High risk detected by local pattern scan")
                add_to_blacklist(url, redis_config.redis_client)
                log_scan_result(url, {"status": "unsafe", "source": "local_pattern_scan", "risk_score": risk_score, "reasons": reasons})
                send_alert(f"High-risk pattern in URL: {url} (Score: {risk_score})")
                return jsonify({
                    "url": url, 
                    "status": "unsafe", 
                    "source": "local_pattern_scan",
                    "risk_score": risk_score,
                    "reasons": reasons
                }), 200
        except Exception as e:
            print(f"[DEBUG] Local scan FAILED: {e}")
            all_reasons.append(f"Local scan error: {str(e)}")

        # 2. VirusTotal scan
        print("[DEBUG] 6. Running VirusTotal scan...")
        virus_total_risk = "low"
        try:
            virus_total_risk = check_url_risk(url)
            print(f"[DEBUG] VirusTotal result: '{virus_total_risk}'")
            if virus_total_risk in ["high", "medium"]:
                scan_sources.append(f"VirusTotal: {virus_total_risk}")
                total_risk_score += 3 if virus_total_risk == "high" else 2
                scan_successful = True
        except Exception as e:
            print(f"[DEBUG] VirusTotal scan FAILED: {e}")
            virus_total_risk = "error"
            all_reasons.append(f"VirusTotal error: {str(e)}")

        # 3. Content analysis (NEW)
        print("[DEBUG] 7. Running content analysis...")
        content_risky = False
        content_analysis = ""
        try:
            content_risky, content_analysis = detect_content_anomalies(url)
            print(f"[DEBUG] Content analysis: risky={content_risky}, analysis='{content_analysis}'")
            if content_risky:
                scan_sources.append("Content analysis")
                total_risk_score += 2
                all_reasons.append(content_analysis)
                scan_successful = True
        except Exception as e:
            print(f"[DEBUG] Content analysis FAILED: {e}")
            all_reasons.append(f"Content analysis error: {str(e)}")

        # 4. Basic web scraping scan
        print("[DEBUG] 8. Running web scraping scan...")
        is_risky = False
        web_scrape_analysis = ""
        try:
            is_risky, web_scrape_analysis = scrape_and_has_form(url)
            print(f"[DEBUG] Web scrape result: is_risky={is_risky}, analysis='{web_scrape_analysis}'")
            if is_risky:
                scan_sources.append("Form detection")
                total_risk_score += 1
                all_reasons.append(web_scrape_analysis)
                scan_successful = True
        except Exception as e:
            print(f"[DEBUG] Web scraping FAILED: {e}")
            all_reasons.append(f"Web scraping error: {str(e)}")

        # Check if scan completely failed
        if not scan_successful:
            print("[DEBUG] ALL SCANS FAILED - returning error")
            return jsonify({
                "error": "All scan methods failed", 
                "url": url,
                "details": all_reasons
            }), 500

        # Final decision with LOWERED THRESHOLD
        print(f"[DEBUG] 9. Making final decision - Total Risk Score: {total_risk_score}")
        print(f"[DEBUG] Risk factors: {scan_sources}")
        
        # LOWERED THRESHOLD: Risk score >= 2 OR any high-confidence indicator
        is_unsafe = (
            total_risk_score >= 2 or  # LOWERED from 5 to 2
            virus_total_risk in ["high", "medium"] or
            content_risky or
            (is_risky and total_risk_score >= 1)
        )
        
        if is_unsafe:
            print("[DEBUG] DECISION: URL is UNSAFE")
            add_to_blacklist(url, redis_config.redis_client)
            send_alert(f"Threat detected: {url} (Risk: {total_risk_score}, Sources: {', '.join(scan_sources)})")
            log_scan_result(url, {
                "status": "unsafe", 
                "source": "scan",
                "risk_score": total_risk_score,
                "scan_sources": scan_sources,
                "reasons": all_reasons
            })
            return jsonify({
                "url": url, 
                "status": "unsafe", 
                "source": "scan",
                "risk_score": total_risk_score,
                "scan_sources": scan_sources,
                "reasons": all_reasons[:5]  # Limit reasons shown
            }), 200
        else:
            print("[DEBUG] DECISION: URL is SAFE")
            add_to_whitelist(url, redis_config.redis_client)
            log_scan_result(url, {
                "status": "safe", 
                "source": "scan",
                "risk_score": total_risk_score
            })
            return jsonify({
                "url": url, 
                "status": "safe", 
                "source": "scan",
                "risk_score": total_risk_score
            }), 200

    except Exception as e:
        print(f"[DEBUG] CRITICAL ERROR in passive_scan: {e}")
        traceback.print_exc()
        return jsonify({
            "error": "Internal server error", 
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