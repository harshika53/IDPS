import requests
from bs4 import BeautifulSoup

# Function to scrape all links from a URL
def scrape_links(url):
    try:
        # Send a GET request to the URL
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # Ensure we received a successful response

        # Parse the HTML content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True)]

        print(f"Found {len(links)} links.")  # Debugging
        return links
    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return []
       

# Function to scrape and filter suspicious links
def scrape_links_with_filter(url):
    try:
        # Send a GET request to the URL
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        
        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        content = soup.get_text().lower()
        print("Extracted Content:", content[:500])  # Log first 500 characters
        
        suspicious_patterns = ["phishing", "malware", "suspicious"]
        if any(pattern in content for pattern in suspicious_patterns):
            print(f"Suspicious pattern found in {url}")
            return [], ["suspicious pattern"]

        return [], []  # No suspicious links
    except Exception as e:
        print(f"Error accessing {url}: {e}")
        return [], []

       
