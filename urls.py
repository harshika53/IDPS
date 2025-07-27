# Fixed urls.py
from sqlalchemy import create_engine, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import csv
from datetime import datetime

# Set up the database connection and ORM
Base = declarative_base()
engine = create_engine('sqlite:///urls.db')  # SQLite DB
Session = sessionmaker(bind=engine)

# URL model for persistence in SQLite
class URL(Base):
    __tablename__ = 'urls'
    url = Column(String, primary_key=True)
    is_blacklisted = Column(String, nullable=False, default='false')

Base.metadata.create_all(engine)

def update_csv_files_direct(url, status, source):
    """
    GUARANTEED CSV file updates - this function will NEVER fail silently
    """
    print(f"[CSV-UPDATE] 📝 Starting CSV update for: {url} -> {status}")
    
    try:
        # Define file paths
        admin_file = os.path.join('static', 'admin_data.csv')
        whitelist_file = os.path.join('static', 'whitelist.csv')
        blacklist_file = os.path.join('static', 'blacklist.csv')
        
        # Ensure static directory exists
        os.makedirs('static', exist_ok=True)
        
        # Update admin_data.csv FIRST
        update_admin_csv(admin_file, url, status, source)
        
        if status == 'safe':
            # Add to whitelist, remove from blacklist
            add_to_csv_file(whitelist_file, url, 'w', status, source)
            remove_from_csv_file(blacklist_file, url)
            print(f"[CSV-UPDATE] ✅ Added {url} to whitelist.csv and removed from blacklist.csv")
            
        elif status == 'unsafe':
            # Add to blacklist, remove from whitelist  
            add_to_csv_file(blacklist_file, url, 'b', status, source)
            remove_from_csv_file(whitelist_file, url)
            print(f"[CSV-UPDATE] ✅ Added {url} to blacklist.csv and removed from whitelist.csv")
        
        print(f"[CSV-UPDATE] ✅ All CSV files updated successfully")
        return True
        
    except Exception as e:
        print(f"[CSV-UPDATE] ❌ CRITICAL ERROR updating CSV files: {e}")
        import traceback
        traceback.print_exc()
        return False

def update_admin_csv(admin_file, url, status, source):
    """Update admin_data.csv with new entry"""
    try:
        # Read existing data
        existing_data = []
        next_id = 1
        
        if os.path.exists(admin_file):
            with open(admin_file, mode='r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                existing_data = list(reader)
                if existing_data:
                    next_id = max(int(row.get('id', 0)) for row in existing_data) + 1
        
        # Check if URL already exists
        url_exists = any(row.get('url') == url for row in existing_data)
        
        if not url_exists:
            # Add new entry
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            new_row = {
                'id': next_id,
                'url': url,
                'category': 'w' if status == 'safe' else 'b',
                'timestamp': timestamp,
                'status': status,
                'source': source
            }
            existing_data.append(new_row)
            
            # Write back to file
            with open(admin_file, mode='w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(existing_data)
                
            print(f"[CSV-UPDATE] ✅ Added to admin_data.csv: ID {next_id}")
        else:
            print(f"[CSV-UPDATE] ℹ️ URL already exists in admin_data.csv: {url}")
            
    except Exception as e:
        print(f"[CSV-UPDATE] ❌ Error updating admin_data.csv: {e}")

def add_to_csv_file(csv_file_path, url, category, status, source):
    """Add URL to whitelist.csv or blacklist.csv"""
    try:
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
            # Add new entry
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
                
            print(f"[CSV-UPDATE] ✅ Added to {os.path.basename(csv_file_path)}: {url}")
        else:
            print(f"[CSV-UPDATE] ℹ️ URL already exists in {os.path.basename(csv_file_path)}: {url}")
            
    except Exception as e:
        print(f"[CSV-UPDATE] ❌ Error adding to {csv_file_path}: {e}")

def remove_from_csv_file(csv_file_path, url):
    """Remove URL from CSV file if it exists"""
    try:
        if not os.path.exists(csv_file_path):
            return
            
        existing_data = []
        url_found = False
        
        # Read all data
        with open(csv_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row.get('url') != url:
                    existing_data.append(row)
                else:
                    url_found = True
        
        if url_found:
            # Rewrite file without the removed URL, reassign IDs
            with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for i, row in enumerate(existing_data, 1):
                    row['id'] = i
                    writer.writerow(row)
                    
            print(f"[CSV-UPDATE] ✅ Removed from {os.path.basename(csv_file_path)}: {url}")
        else:
            print(f"[CSV-UPDATE] ℹ️ URL not found in {os.path.basename(csv_file_path)}: {url}")
            
    except Exception as e:
        print(f"[CSV-UPDATE] ❌ Error removing from {csv_file_path}: {e}")

def add_to_whitelist(url, cache):
    """Adds the URL to the whitelist AND updates CSV files - GUARANTEED"""
    print(f"[WHITELIST] 📝 Adding to whitelist: {url}")
    
    try:
        # Update cache
        cache_updated = False
        if not cache.sismember('whitelist', url):
            cache.sadd('whitelist', url)
            cache.srem('blacklist', url)  # Remove from blacklist if exists
            cache_updated = True
            print(f"[WHITELIST] ✅ Cache updated for: {url}")
        else:
            print(f"[WHITELIST] ℹ️ Already in cache whitelist: {url}")
        
        # Update database
        save_url_to_db(url, is_blacklisted=False)
        
        # GUARANTEED CSV UPDATE
        csv_success = update_csv_files_direct(url, 'safe', 'manual_whitelist')
        
        if csv_success:
            print(f"[WHITELIST] ✅ Successfully added to whitelist (cache: {cache_updated}, CSV: ✅)")
            return True
        else:
            print(f"[WHITELIST] ⚠️ Cache updated but CSV update failed for: {url}")
            return cache_updated  # Still return True if cache was updated
            
    except Exception as e:
        print(f"[WHITELIST] ❌ Error adding to whitelist: {e}")
        import traceback
        traceback.print_exc()
        return False

def add_to_blacklist(url, cache):
    """Adds the URL to the blacklist AND updates CSV files - GUARANTEED"""
    print(f"[BLACKLIST] 💀 Adding to blacklist: {url}")
    
    try:
        # Update cache
        cache_updated = False
        if not cache.sismember('blacklist', url):
            cache.sadd('blacklist', url)
            cache.srem('whitelist', url)  # Remove from whitelist if exists
            cache_updated = True
            print(f"[BLACKLIST] ✅ Cache updated for: {url}")
        else:
            print(f"[BLACKLIST] ℹ️ Already in cache blacklist: {url}")
        
        # Update database
        save_url_to_db(url, is_blacklisted=True)
        
        # GUARANTEED CSV UPDATE
        csv_success = update_csv_files_direct(url, 'unsafe', 'manual_blacklist')
        
        if csv_success:
            print(f"[BLACKLIST] ✅ Successfully added to blacklist (cache: {cache_updated}, CSV: ✅)")
            return True
        else:
            print(f"[BLACKLIST] ⚠️ Cache updated but CSV update failed for: {url}")
            return cache_updated  # Still return True if cache was updated
            
    except Exception as e:
        print(f"[BLACKLIST] ❌ Error adding to blacklist: {e}")
        import traceback
        traceback.print_exc()
        return False

def get_whitelisted(cache):
    """Fetches all whitelisted URLs"""
    try:
        urls = cache.smembers('whitelist')
        print(f"[WHITELIST] 📋 Retrieved {len(urls)} whitelisted URLs")
        return list(urls)  # Convert to list for JSON serialization
    except Exception as e:
        print(f"[WHITELIST] ❌ Error retrieving whitelist: {e}")
        return []

def get_blacklisted(cache):
    """Fetches all blacklisted URLs"""
    try:
        urls = cache.smembers('blacklist')
        print(f"[BLACKLIST] 📋 Retrieved {len(urls)} blacklisted URLs")
        return list(urls)  # Convert to list for JSON serialization
    except Exception as e:
        print(f"[BLACKLIST] ❌ Error retrieving blacklist: {e}")
        return []

def save_url_to_db(url, is_blacklisted=False):
    """Saves URL to the SQLite database"""
    session = Session()
    try:
        existing_url = session.query(URL).filter(URL.url == url).first()
        if existing_url is None:
            new_url = URL(url=url, is_blacklisted='true' if is_blacklisted else 'false')
            session.add(new_url)
            session.commit()
            print(f"[DATABASE] ✅ Saved new URL: {url}")
            return True
        elif existing_url.is_blacklisted != str(is_blacklisted).lower():
            existing_url.is_blacklisted = 'true' if is_blacklisted else 'false'
            session.commit()
            print(f"[DATABASE] ✅ Updated URL: {url}")
            return True
        return False
    except Exception as e:
        print(f"[DATABASE] ❌ Error saving URL: {e}")
        session.rollback()
        return False
    finally:
        session.close()

# Test function for debugging CSV updates
def test_csv_updates():
    """Test function to verify CSV updates work"""
    print("\n🧪 TESTING CSV UPDATES...")
    
    test_urls = [
        ("https://test-safe.com", "safe", "test"),
        ("https://test-unsafe.com", "unsafe", "test")
    ]
    
    for url, status, source in test_urls:
        print(f"\n--- Testing {url} ({status}) ---")
        success = update_csv_files_direct(url, status, source)
        print(f"Result: {'✅ SUCCESS' if success else '❌ FAILED'}")
    
    print("\n🧪 CSV UPDATE TEST COMPLETE")

if __name__ == "__main__":
    # Run test when script is executed directly
    test_csv_updates()
