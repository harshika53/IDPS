# scanner.py

import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Import patterns from your patterns.py file
from patterns import (
    file_ext_pattern,
    phishing_keywords_pattern,
    obfuscation_pattern,
    # Add any other patterns you want to check from patterns.py
)

# Import the Selenium-based web scraper
from webscrapping import get_dynamic_page_content

# --- 1. Heuristic and Pattern-Based URL Analysis ---

def advanced_url_analysis(url):
    """
    Performs heuristic and pattern-based analysis on a URL string.
    Returns a risk score and a list of reasons.
    """
    risk_score = 0
    reasons = []
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Heuristic 1: Check for suspicious TLDs
        suspicious_tlds = ['.zip', '.mov', '.xyz', '.top', '.live', '.info']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            risk_score += 2
            reasons.append("URL uses a suspicious TLD")

        # Heuristic 2: Check for excessive subdomains
        if domain.count('.') > 3:
            risk_score += 1
            reasons.append("URL has an excessive number of subdomains")
            
        # Heuristic 3: Check for IP address in domain
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            risk_score += 3
            reasons.append("URL uses an IP address instead of a domain name")

        # Pattern Check 1: Malicious file extensions
        if re.search(file_ext_pattern, url, re.IGNORECASE):
            risk_score += 5
            reasons.append("URL points to a potentially malicious file type")

        # Pattern Check 2: Phishing keywords
        if re.search(phishing_keywords_pattern, url, re.IGNORECASE):
            risk_score += 2
            reasons.append("URL contains common phishing keywords")

        # Pattern Check 3: Obfuscation patterns
        if re.search(obfuscation_pattern, url):
            risk_score += 3
            reasons.append("URL may contain obfuscated or encoded strings")
            
    except Exception as e:
        reasons.append(f"Error during URL analysis: {e}")

    return risk_score, reasons


# --- 2. Content Anomaly Detection ---

def detect_content_anomalies(url):
    """
    Uses Selenium to fetch the full page content and check for anomalies
    like script tags and obfuscated code.
    Returns a boolean indicating if anomalies were found and a descriptive string.
    """
    # Fetch the fully rendered HTML using the Selenium function
    html_content = get_dynamic_page_content(url)

    if not html_content:
        return False, "Could not fetch page content for anomaly detection."

    soup = BeautifulSoup(html_content, 'html.parser')
    
    anomalies_found = []

    # Anomaly 1: Presence of <script> tags (a simple but useful indicator)
    if soup.find_all('script'):
        anomalies_found.append("JavaScript found on page")

    # Anomaly 2: Check for obfuscated JS code patterns
    # This is a more robust check than the one in the old anomaly_model.py
    obfuscation_patterns = [r'eval\(', r'btoa\(', r'atob\(', r'unescape\(', r'document\.write\(']
    page_text = soup.get_text().lower() # Search the visible text and scripts
    for pattern in obfuscation_patterns:
        if re.search(pattern, page_text):
            anomalies_found.append(f"Potential obfuscation detected ('{pattern[:-2]}')")
            # We only need to find one to be suspicious
            break 
            
    if anomalies_found:
        return True, f"Content Anomaly Detected: {', '.join(anomalies_found)}"
    else:
        return False, "No content anomalies detected."

