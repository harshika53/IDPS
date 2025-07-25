# In webscrapping.py

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import time

def get_dynamic_page_content(url):
    """
    Fetches the full HTML content from a URL after JavaScript has rendered it.
    """
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Runs Chrome in headless mode.
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")

    driver = None # Initialize driver to None
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)

        # Wait for a few seconds to allow JS to load.
        # For more complex sites, you might need more advanced waiting strategies.
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
       
