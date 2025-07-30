# scanner.py - Improved version with better detection

import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Enhanced patterns for better detection
SUSPICIOUS_PATTERNS = {
    # High risk patterns (score 4-5)
    'malicious_extensions': r'\.(exe|zip|rar|scr|bat|cmd|com|pif|vbs|jar)(\?|$)',
    'ip_address': r'https?://(?:\d{1,3}\.){3}\d{1,3}',
    'data_uri': r'^data:',
    'javascript_uri': r'^javascript:',
    'suspicious_ports': r':\d{4,5}(/|$)',  # Non-standard ports
    
    # Medium risk patterns (score 2-3)
    'phishing_keywords': r'(login|signin|verify|secure|account|update|password|bank|paypal|amazon|microsoft|google|apple|netflix|facebook)',
    'url_shorteners': r'(bit\.ly|tinyurl\.com|goo\.gl|is\.gd|t\.co|ow\.ly|v\.g|qr\.ae|short\.link)',
    'suspicious_tlds': r'\.(tk|ml|ga|cf|xyz|top|live|info|biz|work)(/|$)',
    'base64_encoded': r'([A-Za-z0-9+\/=]{20,})',
    'excessive_subdomains': r'^https?://([^./]+\.){4,}',
    
    # Low risk patterns (score 1-2)
    'non_https': r'^http://',
    'suspicious_paths': r'/(admin|login|signin|verify|secure|update|download|install|setup)',
    'query_redirects': r'(\?|\&)(redirect|url|goto|next|return)=',
    'long_url': r'^.{150,}$',
    'homograph_attack': r'[а-я]',  # Cyrillic characters that look like Latin
}

KNOWN_MALICIOUS_DOMAINS = [
    'malware.com', 'phishing.net', 'virus.org', 'scam.info', 'fake-bank.com',
    'badware.net', 'trojan.org', 'spyware.com', 'adware.net', 'ransomware.org',
    'mp3raid.com', 'torrent', 'crack', 'keygen', 'warez', 'pirate'
]

def advanced_url_analysis(url):
    """
    Enhanced URL analysis with better detection capabilities
    Returns a risk score and a list of reasons.
    """
    risk_score = 0
    reasons = []
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
        full_url = url.lower()
        
        print(f"[SCANNER] Analyzing URL: {url}")
        print(f"[SCANNER] Domain: {domain}, Path: {path}")
        
        # Check against known malicious domains
        for malicious in KNOWN_MALICIOUS_DOMAINS:
            if malicious in domain:
                risk_score += 5
                reasons.append(f"Known malicious domain pattern: {malicious}")
                print(f"[SCANNER] Found malicious domain pattern: {malicious}")
        
        # Pattern matching with different risk levels
        for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
            if re.search(pattern, url, re.IGNORECASE):
                if pattern_name in ['malicious_extensions', 'ip_address', 'data_uri', 'javascript_uri', 'suspicious_ports']:
                    score = 4
                elif pattern_name in ['phishing_keywords', 'url_shorteners', 'suspicious_tlds', 'base64_encoded', 'excessive_subdomains']:
                    score = 2
                else:
                    score = 1
                
                risk_score += score
                reasons.append(f"{pattern_name.replace('_', ' ').title()}: +{score} points")
                print(f"[SCANNER] Pattern match: {pattern_name} (+{score})")
        
        # Additional heuristics
        if len(domain.split('.')) > 4:
            risk_score += 2
            reasons.append("Too many subdomains")
        
        if len(url) > 200:
            risk_score += 1
            reasons.append("Extremely long URL")
        
        # Check for mixed case in domain (unusual)
        if domain != domain.lower() and domain != domain.upper():
            risk_score += 1
            reasons.append("Mixed case domain")
        
        # Check for suspicious query parameters
        suspicious_params = ['cmd', 'exec', 'shell', 'eval', 'system', 'passthru']
        for param in suspicious_params:
            if param in query:
                risk_score += 3
                reasons.append(f"Suspicious query parameter: {param}")
        
        print(f"[SCANNER] Final risk score: {risk_score}")
        print(f"[SCANNER] Reasons: {reasons}")
        
    except Exception as e:
        risk_score += 1
        reasons.append(f"URL parsing error: {e}")
        print(f"[SCANNER] Error analyzing URL: {e}")

    return risk_score, reasons

def detect_content_anomalies(url):
    """
    Enhanced content analysis with better detection
    """
    print(f"[CONTENT-SCANNER] Starting content analysis for: {url}")
    
    try:
        # Import here to avoid circular imports
        from webscrapping import get_dynamic_page_content
        
        html_content = get_dynamic_page_content(url)
        if not html_content:
            return False, "Could not fetch page content for analysis"

        soup = BeautifulSoup(html_content, 'html.parser')
        anomalies_found = []
        risk_score = 0

        # Check for suspicious forms
        forms = soup.find_all('form')
        for form in forms:
            # Look for password fields
            if form.find('input', {'type': 'password'}):
                risk_score += 2
                anomalies_found.append("Password form detected")
            
            # Check for suspicious form actions
            action = form.get('action', '').lower()
            if any(word in action for word in ['login', 'signin', 'verify', 'secure']):
                risk_score += 2
                anomalies_found.append("Suspicious form action")

        # Check for suspicious scripts
        scripts = soup.find_all('script')
        for script in scripts:
            script_content = script.get_text().lower()
            if any(word in script_content for word in ['eval(', 'document.write(', 'fromcharcode', 'unescape(']):
                risk_score += 3
                anomalies_found.append("Potentially obfuscated JavaScript")
                break

        # Check for iframes (often used in attacks)
        iframes = soup.find_all('iframe')
        if len(iframes) > 2:
            risk_score += 2
            anomalies_found.append(f"Multiple iframes detected ({len(iframes)})")
        
        # Check for hidden elements (potential phishing)
        hidden_elements = soup.find_all(attrs={'style': re.compile(r'display:\s*none|visibility:\s*hidden', re.I)})
        if len(hidden_elements) > 5:
            risk_score += 1
            anomalies_found.append("Many hidden elements")

        # Check page title for suspicious keywords
        title = soup.find('title')
        if title:
            title_text = title.get_text().lower()
            suspicious_titles = ['warning', 'virus', 'infected', 'alert', 'security', 'update required']
            for word in suspicious_titles:
                if word in title_text:
                    risk_score += 2
                    anomalies_found.append(f"Suspicious page title contains: {word}")
                    break

        print(f"[CONTENT-SCANNER] Content risk score: {risk_score}")
        print(f"[CONTENT-SCANNER] Anomalies: {anomalies_found}")

        if risk_score >= 3 or len(anomalies_found) >= 2:
            return True, f"Content anomalies detected (risk: {risk_score}): {', '.join(anomalies_found)}"
        else:
            return False, "No significant content anomalies detected"
            
    except Exception as e:
        print(f"[CONTENT-SCANNER] Error during content analysis: {e}")
        return False, f"Content analysis failed: {str(e)}"

