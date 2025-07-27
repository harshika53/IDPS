# redis_config.py - Fixed In-Memory Version
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
        print("[CACHE] InMemoryCache instance created")
    
    def _initialize(self):
        """Initialize cache on startup"""
        if not self.initialized:
            print("[CACHE] Initializing cache...")
            self.load_from_file()
            self.load_from_csv()
            self.initialized = True
            print(f"[CACHE] Cache initialized - Whitelist: {len(self.data['whitelist'])}, Blacklist: {len(self.data['blacklist'])}")
            self._debug_cache_contents()
    
    def _debug_cache_contents(self):
        """Debug function to show what's in cache"""
        print(f"[CACHE-DEBUG] Current cache contents:")
        print(f"[CACHE-DEBUG] Whitelist ({len(self.data['whitelist'])}): {list(self.data['whitelist'])[:5]}...")
        print(f"[CACHE-DEBUG] Blacklist ({len(self.data['blacklist'])}): {list(self.data['blacklist'])[:5]}...")
    
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
            # Load from admin_data.csv (primary source)
            admin_file = os.path.join('static', 'admin_data.csv')
            if os.path.exists(admin_file):
                with open(admin_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        url = row['url'].strip()
                        category = row.get('category', '').strip()
                        if category == 'w':
                            self.data['whitelist'].add(url)
                            print(f"[CACHE] Added to whitelist from CSV: {url}")
                        elif category == 'b':
                            self.data['blacklist'].add(url)
                            print(f"[CACHE] Added to blacklist from CSV: {url}")
                print(f"[CACHE] Loaded from admin_data.csv - W:{len([r for r in csv.DictReader(open(admin_file)) if r.get('category')=='w'])}, B:{len([r for r in csv.DictReader(open(admin_file)) if r.get('category')=='b'])}")
                
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
            print(f"[CACHE] Saved cache to {self.cache_file}")
        except Exception as e:
            print(f"[CACHE] Error saving cache file: {e}")
    
    def ping(self):
        """Test connection (always returns True for in-memory)"""
        self._initialize()  # Ensure initialized
        return True
    
    def sismember(self, key, value):
        """Check if value is in set - FIXED VERSION"""
        self._initialize()  # Ensure initialized
        
        original_value = value.strip()
        print(f"[CACHE-LOOKUP] Checking {key} for: '{original_value}'")
        
        # Direct lookup first
        direct_match = original_value in self.data.get(key, set())
        if direct_match:
            print(f"[CACHE-LOOKUP] DIRECT MATCH found in {key}: {original_value}")
            return True
        
        # Try with/without trailing slash
        if original_value.endswith('/'):
            no_slash = original_value.rstrip('/')
            if no_slash in self.data.get(key, set()):
                print(f"[CACHE-LOOKUP] MATCH without slash in {key}: {no_slash}")
                return True
        else:
            with_slash = original_value + '/'
            if with_slash in self.data.get(key, set()):
                print(f"[CACHE-LOOKUP] MATCH with slash in {key}: {with_slash}")
                return True
        
        # Try with protocol normalization only if no protocol present
        if not original_value.startswith(('http://', 'https://')):
            https_version = 'https://' + original_value
            http_version = 'http://' + original_value
            
            if https_version in self.data.get(key, set()):
                print(f"[CACHE-LOOKUP] MATCH with https in {key}: {https_version}")
                return True
            if http_version in self.data.get(key, set()):
                print(f"[CACHE-LOOKUP] MATCH with http in {key}: {http_version}")
                return True
        
        print(f"[CACHE-LOOKUP] NO MATCH found in {key} for: {original_value}")
        
        # Debug: show what's actually in the cache
        cache_contents = list(self.data.get(key, set()))[:3]  # Show first 3 items
        print(f"[CACHE-LOOKUP] {key} contains: {cache_contents}...")
        
        return False
    
    def sadd(self, key, value):
        """Add value to set - SIMPLIFIED VERSION"""
        self._initialize()  # Ensure initialized
        if key not in self.data:
            self.data[key] = set()
        
        # Only add the exact value provided, no normalization
        original_value = value.strip()
        self.data[key].add(original_value)
        
        print(f"[CACHE-ADD] Added to {key}: '{original_value}'")
        self.save_to_file()
        return True
    
    def srem(self, key, value):
        """Remove value from set"""
        self._initialize()  # Ensure initialized
        if key in self.data:
            original_value = value.strip()
            
            # Remove exact match
            if original_value in self.data[key]:
                self.data[key].discard(original_value)
                print(f"[CACHE-REMOVE] Removed from {key}: '{original_value}'")
            
            # Also try variations (with/without slash, with/without protocol)
            variations = [
                original_value.rstrip('/'),
                original_value + '/' if not original_value.endswith('/') else original_value,
            ]
            
            # Add protocol variations if no protocol present
            if not original_value.startswith(('http://', 'https://')):
                variations.extend([
                    'https://' + original_value,
                    'http://' + original_value,
                    'https://' + original_value.rstrip('/'),
                    'http://' + original_value.rstrip('/'),
                ])
            
            for variant in variations:
                if variant in self.data[key]:
                    self.data[key].discard(variant)
                    print(f"[CACHE-REMOVE] Removed variant from {key}: '{variant}'")
            
            self.save_to_file()
            return True
        return False
    
    def smembers(self, key):
        """Get all members of set"""
        self._initialize()  # Ensure initialized
        members = list(self.data.get(key, set()))
        print(f"[CACHE-MEMBERS] {key} has {len(members)} members")
        return members
    
    def delete(self, *keys):
        """Delete keys"""
        self._initialize()  # Ensure initialized
        for key in keys:
            if key in self.data:
                count = len(self.data[key])
                self.data[key] = set()
                print(f"[CACHE-DELETE] Cleared {count} items from {key}")
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