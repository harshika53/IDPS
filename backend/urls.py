import redis  # Correct import of redis
from sqlalchemy import create_engine, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Initialize Redis connection
cache = redis.StrictRedis(host='localhost', port=6379, db=0)

# Set up the database connection and ORM
Base = declarative_base()
engine = create_engine('sqlite:///urls.db')  # SQLite DB
Session = sessionmaker(bind=engine)

# URL model for persistence in SQLite
class URL(Base):
    __tablename__ = 'urls'
    url = Column(String, primary_key=True)

Base.metadata.create_all(engine)

def add_to_whitelist(url, cache):
    """Adds the URL to the whitelist"""
    if not cache.sismember('whitelist', url):
        cache.sadd('whitelist', url)
        return True
    return False

def add_to_blacklist(url, cache):
    """Adds the URL to the blacklist"""
    if not cache.sismember('blacklist', url):
        cache.sadd('blacklist', url)
        return True
    return False

def get_whitelisted(cache):
    """Fetches all whitelisted URLs"""
    return list(cache.smembers('whitelist'))

def get_blacklisted(cache):
    """Fetches all blacklisted URLs"""
    return list(cache.smembers('blacklist'))

def save_url_to_db(url, is_blacklisted=False):
    """Saves URL to the database"""
    session = Session()  # Create a new session for each operation
    try:
        existing_url = session.query(URL).filter(URL.url == url).first()
        if existing_url is None:
            new_url = URL(url=url)
            session.add(new_url)
            session.commit()
            return True
        return False
    finally:
        session.close()  # Ensure session is closed after the operation

