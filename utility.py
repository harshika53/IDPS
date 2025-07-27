# utility.py
import csv
import os
from datetime import datetime

def send_alert(message):
    # Send an alert (e.g., email, logging, or real-time notification)
    print(f"ALERT: {message}")

def log_scan_result(url, result):
    """
    Logs the result of URL scanning into the admin_data.csv file
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
        
    except Exception as e:
        print(f"[DEBUG-UTILITY] Error logging scan result: {e}")
        # Fallback to simple text log
        with open('scan_results.log', 'a') as log_file:
            log_file.write(f"{datetime.now()}: URL: {url} - Result: {result}\n")
