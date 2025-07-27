#!/usr/bin/env python3
"""
Test script to verify CSV updates are working correctly
Run this script to test all CSV operations before running your main app
"""

import os
import sys
import csv
from datetime import datetime

# Add current directory to path so we can import our modules
sys.path.append('.')

def test_csv_structure():
    """Test that CSV files have correct structure"""
    print("🔍 TESTING CSV FILE STRUCTURE...")
    
    required_files = [
        'static/admin_data.csv',
        'static/whitelist.csv', 
        'static/blacklist.csv'
    ]
    
    required_columns = ['id', 'url', 'category', 'timestamp', 'status', 'source']
    
    for file_path in required_files:
        print(f"\n--- Checking {file_path} ---")
        
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    columns = reader.fieldnames
                    rows = list(reader)
                    
                    print(f"✅ File exists: {len(rows)} rows")
                    print(f"📋 Columns: {columns}")
                    
                    missing = [col for col in required_columns if col not in columns]
                    if missing:
                        print(f"❌ Missing columns: {missing}")
                    else:
                        print(f"✅ All required columns present")
                        
            except Exception as e:
                print(f"❌ Error reading file: {e}")
        else:
            print(f"❌ File missing: {file_path}")
    
    print(f"\n✅ CSV STRUCTURE TEST COMPLETE\n")

def test_direct_csv_updates():
    """Test direct CSV update functions"""
    print("🧪 TESTING DIRECT CSV UPDATES...")
    
    try:
        # Import our fixed functions
        from urls import update_csv_files_direct
        
        test_cases = [
            ("https://test-safe-example.com", "safe", "test_script"),
            ("https://test-unsafe-example.com", "unsafe", "test_script"),
            ("https://test-another-safe.com", "safe", "test_script")
        ]
        
        for url, status, source in test_cases:
            print(f"\n--- Testing: {url} ({status}) ---")
            
            success = update_csv_files_direct(url, status, source)
            
            if success:
                print(f"✅ CSV update successful for {url}")
            else:
                print(f"❌ CSV update failed for {url}")
        
        print(f"\n✅ DIRECT CSV UPDATES TEST COMPLETE\n")
        
    except ImportError as e:
        print(f"❌ Cannot import update functions: {e}")
        print("   Make sure you've updated urls.py with the new code")
    except Exception as e:
        print(f"❌ Error testing CSV updates: {e}")

def test_logging_with_csv():
    """Test that log_scan_result triggers CSV updates"""
    print("📝 TESTING LOGGING WITH CSV UPDATES...")
    
    try:
        from utility import log_scan_result
        
        test_logs = [
            {
                "url": "https://log-test-safe.com",
                "result": {"status": "safe", "source": "scan", "risk_score": 0}
            },
            {
                "url": "https://log-test-unsafe.com", 
                "result": {"status": "unsafe", "source": "scan", "risk_score": 15}
            }
        ]
        
        for test in test_logs:
            print(f"\n--- Testing log: {test['url']} ---")
            
            log_scan_result(test['url'], test['result'])
            print(f"✅ Logging completed for {test['url']}")
        
        print(f"\n✅ LOGGING WITH CSV TEST COMPLETE\n")
        
    except ImportError as e:
        print(f"❌ Cannot import log_scan_result: {e}")
        print("   Make sure you've updated utility.py with the new code")
    except Exception as e:
        print(f"❌ Error testing logging: {e}")

def verify_csv_contents():
    """Verify that our test data was actually written to CSV files"""
    print("🔍 VERIFYING CSV CONTENTS AFTER TESTS...")
    
    files_to_check = [
        ('static/admin_data.csv', 'Admin Data'),
        ('static/whitelist.csv', 'Whitelist'),
        ('static/blacklist.csv', 'Blacklist')
    ]
    
    for file_path, file_name in files_to_check:
        print(f"\n--- {file_name} ({file_path}) ---")
        
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)
                    
                    print(f"📊 Total entries: {len(rows)}")
                    
                    # Show last few entries (our test data)
                    test_entries = [row for row in rows if 'test' in row.get('source', '')]
                    
                    if test_entries:
                        print(f"🧪 Test entries found: {len(test_entries)}")
                        for entry in test_entries[-3:]:  # Show last 3 test entries
                            print(f"   • {entry.get('url')} -> {entry.get('status')} ({entry.get('source')})")
                    else:
                        print(f"⚠️ No test entries found in {file_name}")
                        
            except Exception as e:
                print(f"❌ Error reading {file_name}: {e}")
        else:
            print(f"❌ {file_name} file not found")
    
    print(f"\n✅ CSV CONTENTS VERIFICATION COMPLETE\n")

def cleanup_test_data():
    """Remove test data from CSV files"""
    print("🧹 CLEANING UP TEST DATA...")
    
    files_to_clean = [
        'static/admin_data.csv',
        'static/whitelist.csv',
        'static/blacklist.csv'
    ]
    
    for file_path in files_to_clean:
        if os.path.exists(file_path):
            try:
                # Read all data
                with open(file_path, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)
                
                # Remove test entries
                original_count = len(rows)
                cleaned_rows = [row for row in rows if 'test' not in row.get('source', '')]
                
                # Reassign IDs
                for i, row in enumerate(cleaned_rows, 1):
                    row['id'] = i
                
                # Write back
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    if cleaned_rows:
                        writer = csv.DictWriter(f, fieldnames=cleaned_rows[0].keys())
                        writer.writeheader()
                        writer.writerows(cleaned_rows)
                    else:
                        # Write empty file with headers
                        fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                
                removed_count = original_count - len(cleaned_rows)
                print(f"✅ {os.path.basename(file_path)}: Removed {removed_count} test entries")
                
            except Exception as e:
                print(f"❌ Error cleaning {file_path}: {e}")
    
    print(f"\n✅ CLEANUP COMPLETE\n")

def main():
    """Run all tests"""
    print("🚀 STARTING CSV UPDATE TESTS")
    print("=" * 50)
    
    # Test 1: Check file structure
    test_csv_structure()
    
    # Test 2: Test direct CSV updates
    test_direct_csv_updates()
    
    # Test 3: Test logging with CSV updates
    test_logging_with_csv()
    
    # Test 4: Verify contents
    verify_csv_contents()
    
    # Ask user if they want to cleanup
    cleanup_choice = input("🧹 Do you want to remove test data from CSV files? (y/n): ").lower()
    if cleanup_choice == 'y':
        cleanup_test_data()
    else:
        print("ℹ️ Test data left in CSV files for your review")
    
    print("\n🎉 ALL TESTS COMPLETED!")
    print("=" * 50)
    print("If all tests passed, your CSV updates should now work correctly.")
    print("You can now run your main application and scan some URLs to verify.")

if __name__ == "__main__":
    main()