#!/usr/bin/env python3
"""
Utility script to synchronize whitelist.csv and blacklist.csv with admin_data.csv
Run this script to ensure all CSV files are in sync.

Usage: python sync_csv_files.py
"""

import os
import sys
import csv
from datetime import datetime

def sync_csv_files():
    """
    Synchronize whitelist.csv and blacklist.csv from admin_data.csv
    """
    admin_file = os.path.join('static', 'admin_data.csv')
    whitelist_file = os.path.join('static', 'whitelist.csv')
    blacklist_file = os.path.join('static', 'blacklist.csv')
    
    # Check if admin_data.csv exists
    if not os.path.exists(admin_file):
        print("❌ Error: static/admin_data.csv not found")
        print("   Make sure you're running this script from the project root directory")
        return False
    
    try:
        print("🔄 Reading data from admin_data.csv...")
        
        whitelist_data = []
        blacklist_data = []
        total_entries = 0
        
        # Read admin data and separate into whitelist/blacklist
        with open(admin_file, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                total_entries += 1
                if row.get('category') == 'w':
                    whitelist_data.append(row)
                elif row.get('category') == 'b':
                    blacklist_data.append(row)
        
        print(f"📊 Found {total_entries} total entries:")
        print(f"   ✅ Safe URLs (whitelist): {len(whitelist_data)}")
        print(f"   ❌ Unsafe URLs (blacklist): {len(blacklist_data)}")
        
        # Create backup of existing files
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        for file_path in [whitelist_file, blacklist_file]:
            if os.path.exists(file_path):
                backup_path = f"{file_path}.backup_{timestamp}"
                os.rename(file_path, backup_path)
                print(f"💾 Backed up {os.path.basename(file_path)} to {os.path.basename(backup_path)}")
        
        # Write new whitelist.csv
        print("🔄 Creating new whitelist.csv...")
        with open(whitelist_file, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for i, row in enumerate(whitelist_data, 1):
                # Ensure all required fields are present
                row['id'] = i
                if 'timestamp' not in row or not row['timestamp']:
                    row['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if 'status' not in row or not row['status']:
                    row['status'] = 'safe'
                if 'source' not in row or not row['source']:
                    row['source'] = 'manual'
                writer.writerow(row)
        
        # Write new blacklist.csv
        print("🔄 Creating new blacklist.csv...")
        with open(blacklist_file, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for i, row in enumerate(blacklist_data, 1):
                # Ensure all required fields are present
                row['id'] = i
                if 'timestamp' not in row or not row['timestamp']:
                    row['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if 'status' not in row or not row['status']:
                    row['status'] = 'unsafe'
                if 'source' not in row or not row['source']:
                    row['source'] = 'manual'
                writer.writerow(row)
        
        print("✅ Synchronization completed successfully!")
        print(f"   📄 whitelist.csv: {len(whitelist_data)} entries")
        print(f"   📄 blacklist.csv: {len(blacklist_data)} entries")
        print("\n🎉 All CSV files are now synchronized!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during synchronization: {e}")
        return False

def verify_sync():
    """
    Verify that the synchronization was successful
    """
    print("\n🔍 Verifying synchronization...")
    
    files_to_check = [
        ('static/admin_data.csv', 'Admin Data'),
        ('static/whitelist.csv', 'Whitelist'),
        ('static/blacklist.csv', 'Blacklist')
    ]
    
    for file_path, file_name in files_to_check:
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    count = sum(1 for row in reader)
                    print(f"   ✅ {file_name}: {count} entries")
            except Exception as e:
                print(f"   ❌ {file_name}: Error reading file - {e}")
        else:
            print(f"   ❌ {file_name}: File not found")

def main():
    print("🚀 CSV Synchronization Utility")
    print("=" * 40)
    
    # Check if we're in the right directory
    if not os.path.exists('static'):
        print("❌ Error: 'static' directory not found")
        print("   Please run this script from your project root directory")
        sys.exit(1)
    
    # Perform synchronization
    if sync_csv_files():
        verify_sync()
        print("\n💡 Next steps:")
        print("   1. Restart your Flask application")
        print("   2. Test scanning a new URL to verify CSV updates work")
        print("   3. Check the dashboard to see if lists are properly loaded")
    else:
        print("\n❌ Synchronization failed. Please check the error messages above.")
        sys.exit(1)

if __name__ == "__main__":
    main()