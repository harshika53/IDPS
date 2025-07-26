from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import time
import random

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
]

def get_dynamic_page_content(url):
    print("[DEBUG-SELENIUM] Starting Selenium WebDriver...")
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument(f'user-agent={random.choice(USER_AGENTS)}')
    
    driver = None
    try:
        driver = webdriver.Chrome(options=chrome_options)
        print(f"[DEBUG-SELENIUM] Navigating to: {url}")
        driver.get(url)
        time.sleep(3)
        html_content = driver.page_source
        print("[DEBUG-SELENIUM] Successfully fetched page content.")
        return html_content
    except Exception as e:
        print(f"[DEBUG-SELENIUM] CRITICAL ERROR during web scraping: {e}")
        return None
    finally:
        if driver:
            driver.quit()
            print("[DEBUG-SELENIUM] WebDriver quit.")

def scrape_and_has_form(url):
    html = get_dynamic_page_content(url)
    if not html:
        return False, "Could not fetch page content"
        
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    
    if len(forms) > 0:
        return True, f"Phishing risk detected: Found {len(forms)} form(s)."
    else:
        return False, "No forms found."
       
