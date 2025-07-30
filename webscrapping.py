from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import time
import requests

def get_dynamic_page_content(url):
    """
    Fetches the full HTML content from a URL after JavaScript has rendered it.
    Falls back to requests if Selenium fails.
    """
    print(f"[DEBUG-SELENIUM] Starting content fetch for: {url}")
    
    # First try with requests (faster fallback)
    try:
        print("[DEBUG-SELENIUM] Trying requests first...")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200 and len(response.text) > 100:
            print("[DEBUG-SELENIUM] Successfully fetched with requests")
            return response.text
    except Exception as e:
        print(f"[DEBUG-SELENIUM] Requests failed: {e}")
    
    # Fallback to Selenium
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-plugins")
    chrome_options.add_argument("--disable-images")  # Faster loading
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

    driver = None
    try:
        print("[DEBUG-SELENIUM] Starting Selenium WebDriver...")
        # Use webdriver_manager to automatically install and manage chromedriver
        service = ChromeService(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        print(f"[DEBUG-SELENIUM] Navigating to: {url}")
        driver.set_page_load_timeout(15) # Reduced timeout
        driver.get(url)
        time.sleep(2) # Reduced wait time
        html_content = driver.page_source
        
        if len(html_content) > 100:  # Basic validation
            print("[DEBUG-SELENIUM] Successfully fetched page content with Selenium")
            return html_content
        else:
            print("[DEBUG-SELENIUM] Selenium returned empty/minimal content")
            return None
            
    except Exception as e:
        print(f"[DEBUG-SELENIUM] CRITICAL ERROR during Selenium scraping: {e}")
        return None
    finally:
        if driver:
            try:
                driver.quit()
                print("[DEBUG-SELENIUM] WebDriver quit successfully")
            except:
                print("[DEBUG-SELENIUM] Error quitting WebDriver")

def scrape_and_has_form(url):
    """
    Analyzes the scraped content to see if it contains any <form> elements.
    Enhanced with better error handling and analysis.
    """
    print(f"[FORM-SCANNER] Starting form analysis for: {url}")
    
    try:
        html = get_dynamic_page_content(url)
        if not html:
            print("[FORM-SCANNER] Could not fetch page content")
            return False, "Could not fetch page content for form analysis"
            
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        
        if len(forms) == 0:
            print("[FORM-SCANNER] No forms found - likely safe")
            return False, "No forms detected"
        
        # Analyze forms for suspicious patterns
        suspicious_forms = 0
        form_details = []
        
        for i, form in enumerate(forms):
            form_analysis = f"Form {i+1}: "
            
            # Check for password fields
            password_fields = form.find_all('input', {'type': 'password'})
            if password_fields:
                suspicious_forms += 1
                form_analysis += "has password field, "
            
            # Check form action
            action = form.get('action', '').lower()
            if any(keyword in action for keyword in ['login', 'signin', 'verify', 'auth', 'secure']):
                suspicious_forms += 1
                form_analysis += f"suspicious action='{action}', "
            
            # Check for email/username fields
            email_fields = form.find_all('input', {'type': 'email'}) + form.find_all('input', {'name': lambda x: x and 'email' in x.lower()})
            username_fields = form.find_all('input', {'name': lambda x: x and any(term in x.lower() for term in ['user', 'login', 'account'])})
            
            if email_fields or username_fields:
                form_analysis += "has credential fields, "
            
            form_details.append(form_analysis.rstrip(', '))
        
        print(f"[FORM-SCANNER] Found {len(forms)} forms, {suspicious_forms} suspicious")
        
        # Decision logic: suspicious if multiple forms OR any form with password
        if suspicious_forms > 0 or len(forms) > 3:
            analysis_text = f"Suspicious forms detected: {len(forms)} total, {suspicious_forms} suspicious. Details: {'; '.join(form_details[:2])}"
            print(f"[FORM-SCANNER] RISKY: {analysis_text}")
            return True, analysis_text
        else:
            analysis_text = f"Found {len(forms)} form(s) but no suspicious patterns detected"
            print(f"[FORM-SCANNER] SAFE: {analysis_text}")
            return False, analysis_text
            
    except Exception as e:
        error_msg = f"Form analysis failed: {str(e)}"
        print(f"[FORM-SCANNER] ERROR: {error_msg}")
        return False, error_msg
       
