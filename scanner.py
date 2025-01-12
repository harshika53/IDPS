# scanner.py
import re
import requests
from bs4 import BeautifulSoup
from patterns import (file_ext_pattern, phishing_keywords_pattern, 
                      obfuscation_pattern, domain_misspellings_pattern, 
                      form_pattern)

# Function to check if a URL matches malicious patterns
def check_url(url):
    if re.search(file_ext_pattern, url):
        return "Suspicious file extension detected"
    if re.search(phishing_keywords_pattern, url, re.IGNORECASE):
        return "Phishing keywords detected in URL"
    if re.search(obfuscation_pattern, url):
        return "URL is obfuscated (Base64 encoded)"
    if re.search(domain_misspellings_pattern, url):
        return "Suspicious domain name detected"
    return "URL appears safe"

# Function to scrape and scan a webpage for phishing forms
def scrape_and_scan(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Search for potential phishing forms
        form_matches = re.findall(form_pattern, str(soup))
        if form_matches:
            return f"Potential phishing form detected: {form_matches}"
        
        return "Page appears clean"
    except requests.exceptions.RequestException as e:
        return f"Error in processing: {e}"

