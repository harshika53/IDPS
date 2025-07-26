# In webscrapping.py

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import time
import random

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
]

def get_dynamic_page_content(url):
    """
    Updated function with User-Agent rotation and throttling.
    """
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    # Rotate User-Agent
    chrome_options.add_argument(f'user-agent={random.choice(USER_AGENTS)}')

    driver = None
    try:
        # Add a random delay to be less predictable
        time.sleep(random.uniform(1, 4))
        
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        time.sleep(3)
        html_content = driver.page_source
        return html_content
    except Exception as e:
        print(f"Error fetching dynamic content for {url}: {e}")
        return None
    finally:
        if driver:
            driver.quit()

def scrape_and_has_form(url):
    """
    Re-implement the original function to use the new dynamic content fetcher.
    """
    html = get_dynamic_page_content(url)
    if not html:
        return False, "Could not fetch page content"

    soup = BeautifulSoup(html, 'html.parser')
    # The rest of your logic to find forms remains the same
    forms = soup.find_all('form')
    return len(forms) > 0, f"Found {len(forms)} forms"