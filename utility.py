# utility.py - Enhanced with CSV file synchronization
import csv
import os
from datetime import datetime

def send_alert(message):
    # Send an alert (e.g., email, logging, or real-time notification)
    print(f"ALERT: {message}")

def update_csv_files(url, status, source):
    """
    Updates both whitelist.csv and blacklist.csv files based on the scan result
    """
    whitelist_file = os.path.join('static', 'whitelist.csv')
    blacklist_file = os.path.join('static', 'blacklist.csv')
    
    try:
        if status == 'safe':
            # Add to whitelist.csv and remove from blacklist.csv if exists
            add_to_csv_file(whitelist_file, url, 'w', status, source)
            remove_from_csv_file(blacklist_file, url)
            print(f"[DEBUG-CSV] Added {url} to whitelist.csv")
            
        elif status == 'unsafe':
            # Add to blacklist.csv and remove from whitelist.csv if exists
            add_to_csv_file(blacklist_file, url, 'b', status, source)
            remove_from_csv_file(whitelist_file, url)
            print(f"[DEBUG-CSV] Added {url} to blacklist.csv")
            
    except Exception as e:
        print(f"[DEBUG-CSV] Error updating CSV files: {e}")

def add_to_csv_file(csv_file_path, url, category, status, source):
    """
    Adds a URL to the specified CSV file if it doesn't already exist
    """
    try:
        # Check if URL already exists in the file
        existing_data = []
        url_exists = False
        
        if os.path.exists(csv_file_path):
            with open(csv_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                existing_data = list(reader)
                url_exists = any(row['url'] == url for row in existing_data)
        
        if not url_exists:
            # Get next ID
            next_id = 1
            if existing_data:
                next_id = max(int(row.get('id', 0)) for row in existing_data) + 1
            
            # Prepare new row
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            new_row = {
                'id': next_id,
                'url': url,
                'category': category,
                'timestamp': timestamp,
                'status': status,
                'source': source
            }
            
            # Add new row to existing data
            existing_data.append(new_row)
            
            # Write all data back
            with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(existing_data)
                
            print(f"[DEBUG-CSV] Successfully added {url} to {os.path.basename(csv_file_path)}")
        else:
            print(f"[DEBUG-CSV] URL {url} already exists in {os.path.basename(csv_file_path)}")
            
    except Exception as e:
        print(f"[DEBUG-CSV] Error adding to {csv_file_path}: {e}")

def remove_from_csv_file(csv_file_path, url):
    """
    Removes a URL from the specified CSV file if it exists
    """
    try:
        if not os.path.exists(csv_file_path):
            return
            
        existing_data = []
        url_found = False
        
        with open(csv_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row['url'] != url:
                    existing_data.append(row)
                else:
                    url_found = True
        
        if url_found:
            # Rewrite the file without the removed URL and reassign IDs
            with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Reassign sequential IDs
                for i, row in enumerate(existing_data, 1):
                    row['id'] = i
                    writer.writerow(row)
                    
            print(f"[DEBUG-CSV] Removed {url} from {os.path.basename(csv_file_path)}")
            
    except Exception as e:
        print(f"[DEBUG-CSV] Error removing from {csv_file_path}: {e}")

def log_scan_result(url, result):
    """
    Enhanced version that logs to admin_data.csv AND updates whitelist/blacklist CSV files
    """
    log_file_path = os.path.join('static', 'admin_data.csv')
    
    try:
        # Read existing data to get the next ID
        next_id = 1
        existing_data = []
        
        if os.path.exists(log_file_path):
            with open(log_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                existing_data = list(reader)
                if existing_data:
                    # Get the highest ID and increment
                    next_id = max(int(row.get('id', 0)) for row in existing_data) + 1
        
        # Prepare new row
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        status = result.get('status', 'unknown')
        source = result.get('source', 'unknown')
        
        new_row = {
            'id': next_id,
            'url': url,
            'category': 'w' if status == 'safe' else 'b',
            'timestamp': timestamp,
            'status': status,
            'source': source
        }
        
        # Write all data back (including new row)
        existing_data.append(new_row)
        
        with open(log_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in existing_data:
                # Ensure all required fields are present
                if 'timestamp' not in row:
                    row['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if 'status' not in row:
                    row['status'] = 'safe' if row.get('category') == 'w' else 'unsafe'
                if 'source' not in row:
                    row['source'] = 'legacy'
                writer.writerow(row)
        
        print(f"[DEBUG-UTILITY] Logged scan result: {url} -> {status}")
        
        # NEW: Also update the whitelist/blacklist CSV files
        # Only update if this is a new scan result (not from cache)
        if source in ['scan', 'manual_whitelist', 'manual_blacklist']:
            update_csv_files(url, status, source)
        
    except Exception as e:
        print(f"[DEBUG-UTILITY] Error logging scan result: {e}")
        # Fallback to simple text log
        with open('scan_results.log', 'a') as log_file:
            log_file.write(f"{datetime.now()}: URL: {url} - Result: {result}\n")

def sync_all_csv_files():
    """
    Utility function to synchronize all CSV files from admin_data.csv
    Useful for one-time migration or fixing inconsistencies
    """
    admin_file = os.path.join('static', 'admin_data.csv')
    whitelist_file = os.path.join('static', 'whitelist.csv')
    blacklist_file = os.path.join('static', 'blacklist.csv')
    
    try:
        if not os.path.exists(admin_file):
            print("[DEBUG-SYNC] admin_data.csv not found")
            return
            
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
        
        print(f"[DEBUG-SYNC] Synchronized CSV files - Whitelist: {len(whitelist_data)}, Blacklist: {len(blacklist_data)}")
        
    except Exception as e:
        print(f"[DEBUG-SYNC] Error synchronizing CSV files: {e}")
