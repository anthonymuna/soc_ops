# tools/ip_reputation.py
import os
import requests
import json
from langchain.tools import tool

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()

@tool
def get_ip_reputation(ip: str) -> str:
    """
    Check the reputation of an IP address using AbuseIPDB.
    Returns: abuseConfidenceScore (0-100), totalReports, countryCode, isp, usageType, lastReportedAt.
    A score above 50 indicates likely malicious activity.
    """
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY.startswith("<"):
        return json.dumps({
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "countryCode": "N/A",
            "isp": "N/A",
            "usageType": "N/A",
            "lastReportedAt": "N/A",
            "note": "AbuseIPDB key not configured"
        })
        
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return json.dumps({
                "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                "totalReports": data.get("totalReports", 0),
                "countryCode": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "N/A"),
                "usageType": data.get("usageType", "N/A"),
                "lastReportedAt": data.get("lastReportedAt", "N/A")
            })
        else:
            return json.dumps({
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "note": f"AbuseIPDB API returned status code {resp.status_code}: {resp.text}"
            })
    except Exception as e:
        return json.dumps({
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "note": f"AbuseIPDB request failed: {str(e)}"
        })
