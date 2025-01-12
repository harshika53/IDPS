def scan_url(url):
    # A simple placeholder function to "scan" a URL
    if "malicious" in url:
        return "High"
    elif "suspicious" in url:
        return "Medium"
    return "Low"
