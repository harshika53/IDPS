import re
import requests

# Define all the suspicious patterns
patterns = {
    'suspicious_file_extensions': r'\.(exe|zip|rar|js|vbs|dll|bat)$',
    'phishing_keywords': r'login|signin|bank|update|secure|account|verify|password',
    'obfuscation_pattern': r'([A-Za-z0-9+\/=]{6,})',
    'domain_misspellings': r'(bank|secure)\.(com|net|org|gov|co)\.([a-z]+){2,}',
    'suspicious_query_params': r'(\?|\&)((login|password|token|user|id|account|email|ssn)=|.*(?:auth|login|secure|signin))',
    'too_many_subdomains': r'^(?:[a-z0-9-]+\.){3,}[a-z]{2,}$',
    'malicious_domains': r'(login|bank|secure|account)\.phishing\.com|\.ru|\.xyz',
    'non_https': r'^http:\/\/',
    'mixed_content': r'http:\/\/.*?src=.*?(\.jpg|\.js|\.css|\.png|\.pdf|\.xml)',
    'base64_url': r'([A-Za-z0-9+\/=]{6,})',
    'url_shortener': r'(bit\.ly|tinyurl\.com|goo\.gl|is\.gd|t\.co|ow\.ly|v\.g|qr\.ae|y\.hoo\.it)',
    'long_url': r'^.{200,}$',
    'suspicious_paths': r'(login|admin|reset-password|update|account|verify)\.php|\.cgi|\.pl|\.jsp|\.aspx',
    'open_redirect': r'(\?|\&)redirect=(.*?|https?://.*?|www\..*)',
    'js_url': r'^javascript:.*',
    'ssl_warning': r'(your connection is not secure|this site is not secure|certificate error)',
    'user_agent': r'(Mozilla|Chrome|Safari)\/[0-9]{1,2}\.[0-9]{1,2}[A-Za-z]?\s+\([A-Za-z0-9\s\.;\-]*\)[\w\W]+',
    'hidden_field': r'<input[^>]*type="hidden".*?>',
    'xss_payload': r'<script.*?>.*?</script>|javascript:.*?alert\((.*?)\)',
}

# Function to check URL against all patterns
def check_url(url):
    matches = []

    for pattern_name, pattern in patterns.items():
        if re.search(pattern, url):
            matches.append(pattern_name)

    return matches


# Function to check if the URL has phishing content or suspicious elements
def scrape_and_scan(url):
    try:
        # Attempt to request the page
        response = requests.get(url)

        # Check if we have a valid response
        if response.status_code == 200:
            page_content = response.text

            # Check for patterns in the URL
            url_matches = check_url(url)
            if url_matches:
                print(f"URL is suspicious. Matches found: {url_matches}")

            # Check for suspicious form content (if applicable)
            form_pattern = r'<form.*?action="(.*?)".*?>.*?<input.*?(name="(password|username)".*?)</form>'
            form_matches = re.findall(form_pattern, page_content)
            if form_matches:
                print(f"Form detected: {form_matches}")
            else:
                print("No suspicious form found.")

            # Check for XSS, SSL warnings, etc., in content
            xss_matches = re.findall(patterns['xss_payload'], page_content)
            ssl_warning_matches = re.findall(patterns['ssl_warning'], page_content)

            if xss_matches:
                print(f"Potential XSS attempt detected: {xss_matches}")
            if ssl_warning_matches:
                print(f"SSL warning text detected: {ssl_warning_matches}")

        else:
            print(f"Failed to retrieve the page. Status code: {response.status_code}")

    except Exception as e:
        print(f"Error in processing: {e}")


# Example usage: Scan a URL
def run_app(app):
    """
    Runs the Flask app, ensuring the server is started.
    """
    app.run(debug=True)
