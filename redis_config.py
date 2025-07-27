import redis

# Configure Redis client with decode_responses=True to get strings instead of bytes
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

def get_url_from_cache(url, cache_type='whitelist'):
    """Check if URL is in cache."""
    try:
        if cache_type == 'whitelist':
            result = redis_client.sismember('whitelist', url)
            print(f"[DEBUG-REDIS] Whitelist check for '{url}': {result}")
            return result
        elif cache_type == 'blacklist':
            result = redis_client.sismember('blacklist', url)
            print(f"[DEBUG-REDIS] Blacklist check for '{url}': {result}")
            return result
        return False
    except Exception as e:
        print(f"[DEBUG-REDIS] Error checking cache: {e}")
        return False

def update_url_cache(url, status, cache_type='whitelist'):
    """Update the Redis cache with the URL's status."""
    try:
        if cache_type == 'whitelist' and status == "safe":
            redis_client.sadd('whitelist', url)
            redis_client.srem('blacklist', url)  # Remove from blacklist if exists
            print(f"[DEBUG-REDIS] Added '{url}' to whitelist")
        elif cache_type == 'blacklist' and status == "unsafe":
            redis_client.sadd('blacklist', url)
            redis_client.srem('whitelist', url)  # Remove from whitelist if exists
            print(f"[DEBUG-REDIS] Added '{url}' to blacklist")
    except Exception as e:
        print(f"[DEBUG-REDIS] Error updating cache: {e}")

def clear_all_cache():
    """Clear all cache (useful for testing)"""
    try:
        redis_client.delete('whitelist', 'blacklist')
        print("[DEBUG-REDIS] Cleared all cache")
    except Exception as e:
        print(f"[DEBUG-REDIS] Error clearing cache: {e}")

def list_cache_contents():
    """Debug function to list all cached URLs"""
    try:
        whitelist = list(redis_client.smembers('whitelist'))
        blacklist = list(redis_client.smembers('blacklist'))
        print(f"[DEBUG-REDIS] Whitelist: {whitelist}")
        print(f"[DEBUG-REDIS] Blacklist: {blacklist}")
        return whitelist, blacklist
    except Exception as e:
        print(f"[DEBUG-REDIS] Error listing cache: {e}")
        return [], []
