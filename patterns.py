# patterns.py

# Malicious file extensions (e.g., .exe, .zip, .rar)
file_ext_pattern = r'\.(exe|zip|rar|js|vbs|dll|bat)$'

# Phishing keywords in URLs
phishing_keywords_pattern = r'login|signin|verify|secure|account|update|password|bank'


# Obfuscated URLs (Base64-like encoding)
obfuscation_pattern = r'([A-Za-z0-9+\/=]{8,})'

# Suspicious domain names (e.g., slight variations of legitimate domains)
domain_misspellings_pattern = r'(bank|secure)\.(com|net|org|gov|co)\.([a-z]+){2,}'

# Form patterns to detect phishing forms in web content
# Enhanced form pattern to catch bypass or suspicious submit actions
form_pattern = r'<form.*?(name="(password|username|email|cardnumber|securitycode|cvv|ssn|dob|pin)"|type="password"|action=".*(bypass|login|confirm|proceed).*?").*?</form>'

# Detects if URL is HTTP instead of HTTPS
non_https_pattern = r'^http:\/\/'

# Checks for Base64 encoded parts in the URL
base64_url_pattern = r'([A-Za-z0-9+\/=]{6,})'

# Detects common URL shortening services
url_shortener_pattern = r'(bit\.ly|tinyurl\.com|goo\.gl|is\.gd|t\.co|ow\.ly|v\.g|qr\.ae|y\.hoo\.it)'

# Matches excessively long URLs (greater than 200 characters)
long_url_pattern = r'^.{200,}$'

# Detects suspicious paths and filenames commonly used in phishing URLs
suspicious_paths_pattern = r'(login|admin|reset-password|update|account|verify)\.php|\.cgi|\.pl|\.jsp|\.aspx'

# Detects open redirects using "redirect" or "url" query parameters
open_redirect_pattern = r'(\?|\&)redirect=(.*?|https?://.*?|www\..*)'

# Detects JavaScript-based URLs (may be used in phishing or malicious popups)
js_url_pattern = r'^javascript:.*'

# Detects text related to fake SSL certificate warnings in the content
ssl_warning_pattern = r'(your connection is not secure|this site is not secure|certificate error)'

# Detects suspicious user-agent strings
user_agent_pattern = r'(Mozilla|Chrome|Safari)\/[0-9]{1,2}\.[0-9]{1,2}[A-Za-z]?\s+\([A-Za-z0-9\s\.;\-]*\)[\w\W]+'

# Detects suspicious redirection chains
redirect_chain_pattern = r'(https?:\/\/(?:www\.)?[^\/]+\/.*?)(\/|\?|#).*?(?:redirect|forward|go|jump).*?'

# Detects hidden fields that might be used for phishing
hidden_field_pattern = r'<input[^>]*type="hidden".*?>'

# Detects possible XSS attempts within the URL
xss_payload_pattern = r'<script.*?>.*?</script>|javascript:.*?alert\((.*?)\)'

# Detects query parameters that include login, password, token, etc.
suspicious_query_params_pattern = r'(\?|\&)((login|password|token|user|id|account|email|ssn)=|.*(?:auth|login|secure|signin))'

# Matches URLs with too many subdomains, e.g., 'abc.xyz.phishingsite.com'
too_many_subdomains_pattern = r'^(?:[a-z0-9-]+\.){3,}[a-z]{2,}$'

# Known malicious domains or URLs (hardcoded or loaded from a file)
malicious_domains_pattern = r'(login|bank|secure|account)\.phishing\.com|\.ru|\.xyz'

