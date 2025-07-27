# redis_config.py - Improved In-Memory Version
import json
import os
import csv
from datetime import datetime

class InMemoryCache:
    """In-memory replacement for Redis when Redis is not available"""
    
    def __init__(self):
        self.data = {
            'whitelist': set(),
            'blacklist': set()
        }
        self.cache_file = 'cache_backup.json'
        self.initialized = False
        self._initialize()
    
    def _initialize(self):
        """Initialize cache on startup"""
        if not self.initialized:
            print("[CACHE] Initializing cache...")
            self.load_from_file()
            self.load_from_csv()
            self.initialized = True
            print(f"[CACHE] Cache initialized - Whitelist: {len(self.data['whitelist'])}, Blacklist: {len(self.data['blacklist'])}")
    
    def load_from_file(self):
        """Load cache from backup file if it exists"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    self.data['whitelist'] = set(data.get('whitelist', []))
                    self.data['blacklist'] = set(data.get('blacklist', []))
                print(f"[CACHE] Loaded cache from {self.cache_file}")
        except Exception as e:
            print(f"[CACHE] Error loading cache file: {e}")
    
    def load_from_csv(self):
        """Load initial data from CSV files"""
        try:
            # Load whitelist
            whitelist_file = os.path.join('static', 'whitelist.csv')
            if os.path.exists(whitelist_file):
                with open(whitelist_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        self.data['whitelist'].add(row['url'])
                print(f"[CACHE] Loaded {len(self.data['whitelist'])} URLs from whitelist.csv")
            
            # Load blacklist
            blacklist_file = os.path.join('static', 'blacklist.csv')
            if os.path.exists(blacklist_file):
                with open(blacklist_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        self.data['blacklist'].add(row['url'])
                print(f"[CACHE] Loaded {len(self.data['blacklist'])} URLs from blacklist.csv")
            
            # Also load from admin_data.csv as fallback
            admin_file = os.path.join('static', 'admin_data.csv')
            if os.path.exists(admin_file):
                with open(admin_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        url = row['url']
                        category = row.get('category', '')
                        if category == 'w':
                            self.data['whitelist'].add(url)
                        elif category == 'b':
                            self.data['blacklist'].add(url)
                print(f"[CACHE] Also loaded from admin_data.csv")
                
        except Exception as e:
            print(f"[CACHE] Error loading CSV files: {e}")
    
    def save_to_file(self):
        """Save cache to backup file"""
        try:
            data = {
                'whitelist': list(self.data['whitelist']),
                'blacklist': list(self.data['blacklist']),
                'last_updated': datetime.now().isoformat()
            }
            with open(self.cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[CACHE] Error saving cache file: {e}")
    
    def ping(self):
        """Test connection (always returns True for in-memory)"""
        self._initialize()  # Ensure initialized
        return True
    
    def sismember(self, key, value):
        """Check if value is in set"""
        self._initialize()  # Ensure initialized
        
        # Normalize URL for comparison
        normalized_value = self._normalize_url(value)
        original_in_set = value in self.data.get(key, set())
        normalized_in_set = normalized_value in self.data.get(key, set())
        
        return original_in_set or normalized_in_set
    
    def _normalize_url(self, url):
        """Normalize URL for better matching"""
        # Remove trailing slashes
        url = url.rstrip('/')
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url
    
    def sadd(self, key, value):
        """Add value to set"""
        self._initialize()  # Ensure initialized
        if key not in self.data:
            self.data[key] = set()
        
        # Add both original and normalized versions
        self.data[key].add(value)
        normalized = self._normalize_url(value)
        if normalized != value:
            self.data[key].add(normalized)
        
        self.save_to_file()
        return True
    
    def srem(self, key, value):
        """Remove value from set"""
        self._initialize()  # Ensure initialized
        if key in self.data:
            self.data[key].discard(value)
            # Also remove normalized version
            normalized = self._normalize_url(value)
            self.data[key].discard(normalized)
            self.save_to_file()
            return True
        return False
    
    def smembers(self, key):
        """Get all members of set"""
        self._initialize()  # Ensure initialized
        return list(self.data.get(key, set()))
    
    def delete(self, *keys):
        """Delete keys"""
        self._initialize()  # Ensure initialized
        for key in keys:
            if key in self.data:
                self.data[key] = set()
        self.save_to_file()
        return True

# Create the cache instance (will auto-initialize)
redis_client = InMemoryCache()

def get_url_from_cache(url, cache_type='whitelist'):
    """Check if URL is in cache."""
    try:
        result = redis_client.sismember(cache_type, url)
        print(f"[DEBUG-CACHE] {cache_type} check for '{url}': {result}")
        return result
    except Exception as e:
        print(f"[DEBUG-CACHE] Error checking cache: {e}")
        return False

def update_url_cache(url, status, cache_type='whitelist'):
    """Update the cache with the URL's status."""
    try:
        if cache_type == 'whitelist' and status == "safe":
            redis_client.sadd('whitelist', url)
            redis_client.srem('blacklist', url)
            print(f"[DEBUG-CACHE] Added '{url}' to whitelist")
        elif cache_type == 'blacklist' and status == "unsafe":
            redis_client.sadd('blacklist', url)
            redis_client.srem('whitelist', url)
            print(f"[DEBUG-CACHE] Added '{url}' to blacklist")
    except Exception as e:
        print(f"[DEBUG-CACHE] Error updating cache: {e}")

def clear_all_cache():
    """Clear all cache"""
    try:
        redis_client.delete('whitelist', 'blacklist')
        print("[DEBUG-CACHE] Cleared all cache")
    except Exception as e:
        print(f"[DEBUG-CACHE] Error clearing cache: {e}")

def list_cache_contents():
    """Debug function to list all cached URLs"""
    try:
        whitelist = redis_client.smembers('whitelist')
        blacklist = redis_client.smembers('blacklist')
        print(f"[DEBUG-CACHE] Whitelist: {whitelist}")
        print(f"[DEBUG-CACHE] Blacklist: {blacklist}")
        return whitelist, blacklist
    except Exception as e:
        print(f"[DEBUG-CACHE] Error listing cache: {e}")
        return [], []