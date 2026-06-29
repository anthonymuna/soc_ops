import urllib.request
import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger("django")

def fetch_rss_feed(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            xml_data = response.read()
            root = ET.fromstring(xml_data)
            items = []
            for item in root.findall('./channel/item'):
                title = item.find('title').text if item.find('title') is not None else ""
                link = item.find('link').text if item.find('link') is not None else ""
                pubDate = item.find('pubDate').text if item.find('pubDate') is not None else ""
                items.append({
                    "title": title,
                    "link": link,
                    "pubDate": pubDate
                })
            return items
    except Exception as e:
        logger.error(f"Error fetching RSS from {url}: {e}")
        return []

def get_threat_advisories():
    bc_url = "https://www.bleepingcomputer.com/feed/"
    items = fetch_rss_feed(bc_url)
    
    # Filter for Kenya/East Africa or critical threats
    filtered = []
    keywords = ["kenya", "africa", "cisa", "ransomware", "breach", "zero-day", "apt", "cve"]
    
    for item in items:
        title_lower = item["title"].lower()
        if any(k in title_lower for k in keywords):
            filtered.append(item)
            
    # If none matched the specific keywords, return the top 10 latest so the ticker isn't empty
    if not filtered:
        return items[:10]
        
    return filtered[:10]
