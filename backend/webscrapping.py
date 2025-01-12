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
        
        # Find all hyperlinks on the page
        links = [a['href'] for a in soup.find_all('a', href=True)]

        print(f"Found {len(links)} links.")  # Print the count of links found
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
        
        # Extract all hyperlinks
        links = [a['href'] for a in soup.find_all('a', href=True)]
        
        # Filter out suspicious links
        suspicious_links = []
        for link in links:
            # Expanded filter conditions with more URL shorteners and example domains
            if "bit.ly" in link or "tinyurl" in link or "shorturl" in link or "suspiciousdomain.com" in link:
                print(f"Suspicious link found: {link}")  # Debugging statement for each suspicious link
                suspicious_links.append(link)

        # Print total links and suspicious links found
        print(f"Total links found: {len(links)}")
        print(f"Total suspicious links found: {len(suspicious_links)}")
        return links, suspicious_links
    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return [], []

# Test the functions
links, suspicious_links = scrape_links_with_filter('https://en.wikipedia.org/wiki/Main_Page')
print("All Links Found:", links)
print("Suspicious Links:", suspicious_links)
