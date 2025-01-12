# utils.py

def send_alert(message):
    # Send an alert (e.g., email, logging, or real-time notification)
    print(f"ALERT: {message}")

def log_scan_result(url, result):
    # Logs the result of URL scanning into a log file (for auditing or future analysis)
    with open('scan_results.log', 'a') as log_file:
        log_file.write(f"URL: {url} - Result: {result}\n")
