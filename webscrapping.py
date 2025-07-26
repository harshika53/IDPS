from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import time

def get_dynamic_page_content(url):
    """
    Fetches the full HTML content from a URL after JavaScript has rendered it.
    This version uses webdriver_manager for reliable driver setup.
    """
    print("[DEBUG-SELENIUM] Starting Selenium WebDriver...")
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

    driver = None
    try:
        # Use webdriver_manager to automatically handle the chromedriver
        service = ChromeService(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        print(f"[DEBUG-SELENIUM] Navigating to: {url}")
        driver.get(url)
        time.sleep(3) # Wait for JS to potentially load
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
    """
    Analyzes the scraped content to see if it contains any <form> elements.
    """
    html = get_dynamic_page_content(url)
    if not html:
        return False, "Could not fetch page content"
        
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    
    if len(forms) > 0:
        return True, f"Phishing risk detected: Found {len(forms)} form(s)."
    else:
        return False, "No forms found."
       
