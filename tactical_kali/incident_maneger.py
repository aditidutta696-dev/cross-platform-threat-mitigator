import requests
import sys
import json
import os
from dotenv import load_dotenv

load_dotenv()

def log_to_thehive(ip, report_file):
    url = f"{os.getenv('THEHIVE_URL')}/api/case"
    headers = {'Authorization': f"Bearer {os.getenv('THEHIVE_API_KEY')}", 'Content-Type': 'application/json'}
    
    with open(report_file, 'r') as f:
        report_data = f.read()

    case = {
        "title": f"AI Intrusion Alert: {ip}",
        "description": f"Automated scan results:\n{report_data[:500]}",
        "severity": 3,
        "tags": ["AI_DETECTION", "KALI_SCAN"]
    }
    
    # Send to TheHive
    requests.post(url, headers=headers, data=json.dumps(case))
    print(f"📂 Incident logged for IP: {ip}")

if __name__ == "__main__":
    log_to_thehive(sys.argv[1], sys.argv[2])
