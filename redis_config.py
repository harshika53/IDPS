import redis

# Configure Redis client
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

def get_url_from_cache(url, cache_type='whitelist'):
    """Check if URL is in cache."""
    if cache_type == 'whitelist':
        return redis_client.sismember('whitelist', url)
    elif cache_type == 'blacklist':
        return redis_client.sismember('blacklist', url)
    return False

def update_url_cache(url, status, cache_type='whitelist'):
    """Update the Redis cache with the URL's status."""
    if cache_type == 'whitelist' and status == "safe":
        redis_client.sadd('whitelist', url)
    elif cache_type == 'blacklist' and status == "unsafe":
        redis_client.sadd('blacklist', url)
