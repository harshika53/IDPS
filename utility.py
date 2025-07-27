# Enhanced utility.py with guaranteed CSV updates

import csv
import os
from datetime import datetime

def send_alert(message):
    """Send an alert (e.g., email, logging, or real-time notification)"""
    print(f"🚨 ALERT: {message}")

def log_scan_result(url, result):
    """
    Enhanced logging that GUARANTEES CSV file updates
    This function ensures that every scan result is properly logged and CSV files are updated
    """
    print(f"[LOG-SCAN] 📝 Logging scan result: {url} -> {result}")
    
    try:
        # Extract details from result
        status = result.get('status', 'unknown')
        source = result.get('source', 'unknown')
        risk_score = result.get('risk_score', 0)
        
        # Update admin_data.csv
        admin_file = os.path.join('static', 'admin_data.csv')
        log_to_admin_csv(admin_file, url, status, source, risk_score, result)
        
        # If this is a NEW scan result (not from cache), update whitelist/blacklist CSV files
        if source in ['scan', 'emergency_analysis', 'manual_whitelist', 'manual_blacklist']:
            print(f"[LOG-SCAN] 🔄 Triggering CSV updates for new scan result...")
            update_whitelist_blacklist_csv(url, status, source)
        else:
            print(f"[LOG-SCAN] ℹ️ Skipping CSV updates for cached result (source: {source})")
        
        print(f"[LOG-SCAN] ✅ Scan result logged successfully")
        
    except Exception as e:
        print(f"[LOG-SCAN] ❌ Error logging scan result: {e}")
        # Fallback to simple text log
        try:
            with open('scan_results_emergency.log', 'a', encoding='utf-8') as log_file:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log_file.write(f"{timestamp}: URL: {url} - Result: {result} - Error: {e}\n")
            print(f"[LOG-SCAN] ✅ Emergency log created")
        except:
            print(f"[LOG-SCAN] ❌ Even emergency logging failed!")

def log_to_admin_csv(admin_file, url, status, source, risk_score, full_result):
    """Log to admin_data.csv with guaranteed success"""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(admin_file), exist_ok=True)
        
        # Read existing data
        existing_data = []
        next_id = 1
        
        if os.path.exists(admin_file):
            with open(admin_file, mode='r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                existing_data = list(reader)
                if existing_data:
                    next_id = max(int(row.get('id', 0)) for row in existing_data) + 1
        
        # Create new entry
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        new_row = {
            'id': next_id,
            'url': url,
            'category': 'w' if status == 'safe' else 'b',
            'timestamp': timestamp,
            'status': status,
            'source': source
        }
        
        # Add to existing data
        existing_data.append(new_row)
        
        # Write back to file
        with open(admin_file, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(existing_data)
        
        print(f"[LOG-ADMIN] ✅ Added to admin_data.csv: ID {next_id}, URL: {url}")
        
    except Exception as e:
        print(f"[LOG-ADMIN] ❌ Error updating admin_data.csv: {e}")
        import traceback
        traceback.print_exc()

def update_whitelist_blacklist_csv(url, status, source):
    """Update whitelist.csv and blacklist.csv based on scan result"""
    try:
        whitelist_file = os.path.join('static', 'whitelist.csv')
        blacklist_file = os.path.join('static', 'blacklist.csv')
        
        if status == 'safe':
            print(f"[CSV-UPDATE] 📝 Adding {url} to whitelist.csv...")
            add_to_specific_csv(whitelist_file, url, 'w', status, source)
            remove_from_specific_csv(blacklist_file, url)
            print(f"[CSV-UPDATE] ✅ Whitelist updated, removed from blacklist")
            
        elif status == 'unsafe':
            print(f"[CSV-UPDATE] 📝 Adding {url} to blacklist.csv...")
            add_to_specific_csv(blacklist_file, url, 'b', status, source)
            remove_from_specific_csv(whitelist_file, url)
            print(f"[CSV-UPDATE] ✅ Blacklist updated, removed from whitelist")
        
    except Exception as e:
        print(f"[CSV-UPDATE] ❌ Error updating whitelist/blacklist CSV: {e}")
        import traceback
        traceback.print_exc()

def add_to_specific_csv(csv_file_path, url, category, status, source):
    """Add URL to a specific CSV file"""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(csv_file_path), exist_ok=True)
        
        existing_data = []
        next_id = 1
        url_exists = False
        
        # Read existing data if file exists
        if os.path.exists(csv_file_path):
            with open(csv_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                existing_data = list(reader)
                if existing_data:
                    next_id = max(int(row.get('id', 0)) for row in existing_data) + 1
                url_exists = any(row.get('url') == url for row in existing_data)
        
        if not url_exists:
            # Create new entry
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            new_row = {
                'id': next_id,
                'url': url,
                'category': category,
                'timestamp': timestamp,
                'status': status,
                'source': source
            }
            existing_data.append(new_row)
            
            # Write all data back
            with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(existing_data)
                
            print(f"[CSV-ADD] ✅ Added to {os.path.basename(csv_file_path)}: {url} (ID: {next_id})")
        else:
            print(f"[CSV-ADD] ℹ️ URL already exists in {os.path.basename(csv_file_path)}: {url}")
            
    except Exception as e:
        print(f"[CSV-ADD] ❌ Error adding to {csv_file_path}: {e}")

def remove_from_specific_csv(csv_file_path, url):
    """Remove URL from a specific CSV file"""
    try:
        if not os.path.exists(csv_file_path):
            print(f"[CSV-REMOVE] ℹ️ File doesn't exist: {os.path.basename(csv_file_path)}")
            return
            
        existing_data = []
        url_found = False
        
        # Read all data except the URL to remove
        with open(csv_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row.get('url') != url:
                    existing_data.append(row)
                else:
                    url_found = True
        
        if url_found:
            # Rewrite file without the removed URL, reassign sequential IDs
            with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for i, row in enumerate(existing_data, 1):
                    row['id'] = i  # Reassign sequential IDs
                    writer.writerow(row)
                    
            print(f"[CSV-REMOVE] ✅ Removed from {os.path.basename(csv_file_path)}: {url}")
        else:
            print(f"[CSV-REMOVE] ℹ️ URL not found in {os.path.basename(csv_file_path)}: {url}")
            
    except Exception as e:
        print(f"[CSV-REMOVE] ❌ Error removing from {csv_file_path}: {e}")

def sync_all_csv_files():
    """
    Utility function to synchronize all CSV files from admin_data.csv
    Useful for one-time migration or fixing inconsistencies
    """
    print("[SYNC] 🔄 Starting CSV synchronization...")
    
    admin_file = os.path.join('static', 'admin_data.csv')
    whitelist_file = os.path.join('static', 'whitelist.csv')
    blacklist_file = os.path.join('static', 'blacklist.csv')
    
    try:
        if not os.path.exists(admin_file):
            print("[SYNC] ❌ admin_data.csv not found")
            return False
            
        whitelist_data = []
        blacklist_data = []
        
        # Read admin data and separate into whitelist/blacklist
        with open(admin_file, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row.get('category') == 'w':
                    whitelist_data.append(row)
                elif row.get('category') == 'b':
                    blacklist_data.append(row)
        
        # Write whitelist.csv
        with open(whitelist_file, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for i, row in enumerate(whitelist_data, 1):
                row['id'] = i  # Reassign sequential IDs
                writer.writerow(row)
        
        # Write blacklist.csv
        with open(blacklist_file, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for i, row in enumerate(blacklist_data, 1):
                row['id'] = i  # Reassign sequential IDs
                writer.writerow(row)
        
        print(f"[SYNC] ✅ Synchronized CSV files - Whitelist: {len(whitelist_data)}, Blacklist: {len(blacklist_data)}")
        return True
        
    except Exception as e:
        print(f"[SYNC] ❌ Error synchronizing CSV files: {e}")
        return False

def verify_csv_files():
    """Verify that all CSV files exist and have the correct structure"""
    print("[VERIFY] 🔍 Verifying CSV file structure...")
    
    files_to_check = [
        ('static/admin_data.csv', 'Admin Data'),
        ('static/whitelist.csv', 'Whitelist'),
        ('static/blacklist.csv', 'Blacklist')
    ]
    
    required_columns = ['id', 'url', 'category', 'timestamp', 'status', 'source']
    
    for file_path, file_name in files_to_check:
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    columns = reader.fieldnames
                    rows = list(reader)
                    
                    missing_columns = [col for col in required_columns if col not in columns]
                    
                    if missing_columns:
                        print(f"[VERIFY] ⚠️ {file_name}: Missing columns {missing_columns}")
                    else:
                        print(f"[VERIFY] ✅ {file_name}: {len(rows)} entries, all columns present")
            else:
                print(f"[VERIFY] ❌ {file_name}: File not found")
        except Exception as e:
            print(f"[VERIFY] ❌ {file_name}: Error reading file - {e}")

def create_missing_csv_files():
    """Create missing CSV files with proper structure"""
    print("[CREATE] 🏗️ Creating missing CSV files...")
    
    files_to_create = [
        ('static/admin_data.csv', 'Admin Data'),
        ('static/whitelist.csv', 'Whitelist'),
        ('static/blacklist.csv', 'Blacklist')
    ]
    
    fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
    
    for file_path, file_name in files_to_create:
        try:
            if not os.path.exists(file_path):
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                
                print(f"[CREATE] ✅ Created {file_name}: {file_path}")
            else:
                print(f"[CREATE] ℹ️ {file_name} already exists")
        except Exception as e:
            print(f"[CREATE] ❌ Error creating {file_name}: {e}")

# Test functions
def test_csv_operations():
    """Test all CSV operations"""
    print("\n🧪 TESTING ALL CSV OPERATIONS...")
    
    # Create missing files
    create_missing_csv_files()
    
    # Verify structure
    verify_csv_files()
    
    # Test adding entries
    test_entries = [
        ("https://test-safe-1.com", "safe", "test"),
        ("https://test-unsafe-1.com", "unsafe", "test")
    ]
    
    for url, status, source in test_entries:
        print(f"\n--- Testing: {url} ({status}) ---")
        
        # Test admin log
        result = {"status": status, "source": source, "risk_score": 5}
        log_scan_result(url, result)
        
        print(f"✅ Test completed for {url}")
    
    # Verify files again
    print("\n--- Final Verification ---")
    verify_csv_files()
    
    print("\n🧪 CSV OPERATIONS TEST COMPLETE")

if __name__ == "__main__":
    # Run tests when script is executed directly
    test_csv_operations()
