from sqlalchemy import create_engine, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from utility import update_csv_files  # Import the new CSV update function

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

def add_to_whitelist(url, cache):
    """Adds the URL to the whitelist AND updates CSV files"""
    print(f"[DEBUG-URLS] Adding to whitelist: {url}")
    if not cache.sismember('whitelist', url):
        cache.sadd('whitelist', url)
        # Remove from blacklist if it exists there
        cache.srem('blacklist', url)
        save_url_to_db(url, is_blacklisted=False)
        
        # NEW: Update CSV files
        try:
            update_csv_files(url, 'safe', 'manual_whitelist')
            print(f"[DEBUG-URLS] Successfully added to whitelist and updated CSV: {url}")
        except Exception as e:
            print(f"[DEBUG-URLS] Error updating CSV files: {e}")
        
        return True
    print(f"[DEBUG-URLS] URL already in whitelist: {url}")
    return False

def add_to_blacklist(url, cache):
    """Adds the URL to the blacklist AND updates CSV files"""
    print(f"[DEBUG-URLS] Adding to blacklist: {url}")
    if not cache.sismember('blacklist', url):
        cache.sadd('blacklist', url)
        # Remove from whitelist if it exists there
        cache.srem('whitelist', url)
        save_url_to_db(url, is_blacklisted=True)
        
        # NEW: Update CSV files
        try:
            update_csv_files(url, 'unsafe', 'manual_blacklist')
            print(f"[DEBUG-URLS] Successfully added to blacklist and updated CSV: {url}")
        except Exception as e:
            print(f"[DEBUG-URLS] Error updating CSV files: {e}")
        
        return True
    print(f"[DEBUG-URLS] URL already in blacklist: {url}")
    return False

def get_whitelisted(cache):
    """Fetches all whitelisted URLs"""
    urls = cache.smembers('whitelist')
    print(f"[DEBUG-URLS] Retrieved {len(urls)} whitelisted URLs")
    return urls

def get_blacklisted(cache):
    """Fetches all blacklisted URLs"""
    urls = cache.smembers('blacklist')
    print(f"[DEBUG-URLS] Retrieved {len(urls)} blacklisted URLs")
    return urls

def save_url_to_db(url, is_blacklisted=False):
    """Saves URL to the database"""
    session = Session()  # Create a new session for each operation
    try:
        existing_url = session.query(URL).filter(URL.url == url).first()
        if existing_url is None:
          new_url = URL(url=url, is_blacklisted='true' if is_blacklisted else 'false')
          session.add(new_url)
          session.commit()
          print(f"[DEBUG-URLS] Saved new URL to DB: {url}")
          return True
        elif existing_url.is_blacklisted != str(is_blacklisted).lower():
            existing_url.is_blacklisted = 'true' if is_blacklisted else 'false'
            session.commit()
            print(f"[DEBUG-URLS] Updated URL in DB: {url}")
            return True
        return False
    finally:
        session.close()
