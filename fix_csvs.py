import csv
import os
from datetime import datetime, timedelta

def fix_csv_files():
    """
    Fix the CSV files to have consistent structure
    """
    base_time = datetime(2025, 1, 15, 10, 0, 0)
    
    # Fixed admin_data.csv
    admin_data = [
        {"id": 1, "url": "https://www.google.com", "category": "w", "timestamp": "2025-01-15 10:00:00", "status": "safe", "source": "manual"},
        {"id": 2, "url": "https://www.facebook.com", "category": "w", "timestamp": "2025-01-15 10:01:00", "status": "safe", "source": "manual"},
        {"id": 3, "url": "http://mp3raid.com/music/krizz_kaliko.html", "category": "b", "timestamp": "2025-01-15 10:02:00", "status": "unsafe", "source": "manual"},
        {"id": 4, "url": "bopsecrets.org/rexroth/cr/1.htm", "category": "b", "timestamp": "2025-01-15 10:03:00", "status": "unsafe", "source": "manual"},
        {"id": 5, "url": "http://espn.go.com/nba/player/_/id/3457/brandon-rush", "category": "b", "timestamp": "2025-01-15 10:04:00", "status": "unsafe", "source": "manual"},
        {"id": 6, "url": "http://yourbittorrent.com/?q=anthony-hamilton-soulife", "category": "b", "timestamp": "2025-01-15 10:05:00", "status": "unsafe", "source": "manual"},
        {"id": 7, "url": "http://www.pashminaonline.com/pure-pashminas", "category": "b", "timestamp": "2025-01-15 10:06:00", "status": "unsafe", "source": "manual"},
        {"id": 8, "url": "http://allmusic.com/album/crazy-from-the-heat-r16990", "category": "b", "timestamp": "2025-01-15 10:07:00", "status": "unsafe", "source": "manual"},
        {"id": 9, "url": "http://www.ikenmijnkunst.nl/index.php/exposities/exposities-2006", "category": "b", "timestamp": "2025-01-15 10:08:00", "status": "unsafe", "source": "manual"},
        {"id": 10, "url": "http://www.szabadmunkaero.hu/cimoldal.html?start=12", "category": "b", "timestamp": "2025-01-15 10:09:00", "status": "unsafe", "source": "manual"},
        {"id": 11, "url": "https://www.eci.gov.in/", "category": "w", "timestamp": "2025-01-15 10:10:00", "status": "safe", "source": "manual"},
        {"id": 12, "url": "https://www.truemeds.in/", "category": "w", "timestamp": "2025-01-15 10:11:00", "status": "safe", "source": "manual"},
        {"id": 13, "url": "https://www.makemytrip.com/", "category": "w", "timestamp": "2025-01-15 10:12:00", "status": "safe", "source": "manual"},
        {"id": 14, "url": "https://www.reddit.com/", "category": "w", "timestamp": "2025-01-15 10:13:00", "status": "safe", "source": "manual"},
        {"id": 15, "url": "https://brainly.in/", "category": "w", "timestamp": "2025-01-15 10:14:00", "status": "safe", "source": "manual"},
        {"id": 16, "url": "https://youtube.com/", "category": "w", "timestamp": "2025-01-15 10:15:00", "status": "safe", "source": "manual"},
        {"id": 17, "url": "https://discord.com/", "category": "w", "timestamp": "2025-01-15 10:16:00", "status": "safe", "source": "manual"},
        {"id": 18, "url": "http://www.amazon.com", "category": "w", "timestamp": "2025-01-15 10:17:00", "status": "safe", "source": "manual"},
    ]
    
    # Create static directory if it doesn't exist
    os.makedirs('static', exist_ok=True)
    
    # Write admin_data.csv
    with open('static/admin_data.csv', 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(admin_data)
    
    # Create whitelist.csv (only safe URLs)
    whitelist_data = [row for row in admin_data if row['category'] == 'w']
    with open('static/whitelist.csv', 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        # Re-number IDs for whitelist
        for i, row in enumerate(whitelist_data, 1):
            row['id'] = i
            writer.writerow(row)
    
    # Create blacklist.csv (only unsafe URLs)
    blacklist_data = [row for row in admin_data if row['category'] == 'b']
    # Add the malformed URL that was in your original blacklist
    blacklist_data.append({
        "id": len(blacklist_data) + 1,
        "url": "http://adventure-nicaragua.net/index.php?option=com_mailto&tmpl=component&link=aHR0cDovL2FkdmVudHVyZS1uaWNhcmFndWEubmV0L2luZGV4LnBocD9vcHRpb249Y29tX2NvbnRlbnQmdmlldz1hcnRpY2xlJmlkPTQ3OmFib3V0JmNhdGlkPTM2OmRlbW8tYXJ0aWNsZXMmSXRlbWlkPTU0",
        "category": "b",
        "timestamp": "2025-01-15 10:18:00",
        "status": "unsafe",
        "source": "manual"
    })
    blacklist_data.append({
        "id": len(blacklist_data) + 1,
        "url": "http://www.lebensmittel-ueberwachung.de/index.php/aktuelles.1",
        "category": "b",
        "timestamp": "2025-01-15 10:19:00",
        "status": "unsafe",
        "source": "manual"
    })
    
    with open('static/blacklist.csv', 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['id', 'url', 'category', 'timestamp', 'status', 'source']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        # Re-number IDs for blacklist
        for i, row in enumerate(blacklist_data, 1):
            row['id'] = i
            writer.writerow(row)
    
    print("✅ CSV files have been fixed!")
    print(f"✅ admin_data.csv: {len(admin_data)} entries")
    print(f"✅ whitelist.csv: {len(whitelist_data)} entries")
    print(f"✅ blacklist.csv: {len(blacklist_data)} entries")

if __name__ == "__main__":
    fix_csv_files()