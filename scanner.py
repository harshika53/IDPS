# In scanner.py

import re
from urllib.parse import urlparse

# Keep your existing patterns from patterns.py
from patterns import MALICIOUS_PATTERNS, PHISHING_KEYWORDS

def advanced_url_analysis(url):
    """
    Performs heuristic analysis on a URL to identify suspicious characteristics.
    Returns a risk score and a list of reasons.
    """
    risk_score = 0
    reasons = []
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path

        # 1. Suspicious TLDs
        suspicious_tlds = ['.zip', '.mov', '.xyz', '.top', '.live', '.info']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            risk_score += 2
            reasons.append("Suspicious TLD")

        # 2. Excessive number of subdomains (e.g., login.account.secure.paypal.com.hacker.net)
        if domain.count('.') > 3:
            risk_score += 1
            reasons.append("Excessive subdomains")
            
        # 3. Presence of IP address in domain
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            risk_score += 3
            reasons.append("IP address used as domain")

        # 4. Use existing regex patterns
        if re.search(MALICIOUS_PATTERNS, url, re.IGNORECASE):
            risk_score += 5
            reasons.append("Matched a known malicious pattern")

        # 5. Phishing keywords in path or domain
        if any(keyword in url.lower() for keyword in PHISHING_KEYWORDS):
            risk_score += 2
            reasons.append("Contains phishing keywords")
            
    except Exception as e:
        reasons.append(f"Error during analysis: {e}")

    return risk_score, reasons

# You would then update your main logic in app.py to use this function
# A risk_score > 5 could be considered malicious, for example.

