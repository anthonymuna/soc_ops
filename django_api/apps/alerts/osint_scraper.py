import urllib.request
import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger("django")

GEO_MAPPING = {
    "kenya": [-1.2921, 36.8219],
    "nairobi": [-1.2921, 36.8219],
    "mombasa": [-4.0435, 39.6682],
    "uganda": [1.3733, 32.2903],
    "tanzania": [-6.3690, 34.8888],
    "east africa": [-1.2921, 36.8219],
    "middle east": [25.2048, 55.2708],
    "europe": [51.1657, 10.4515],
    "russia": [55.7558, 37.6173],
    "russian": [55.7558, 37.6173],
    "china": [39.9042, 116.4074],
    "chinese": [39.9042, 116.4074],
    "iran": [35.6892, 51.3890],
    "iranian": [35.6892, 51.3890],
    "north korea": [39.0392, 125.7625],
    "dprk": [39.0392, 125.7625],
    "us": [38.9072, -77.0369],
    "usa": [38.9072, -77.0369],
    "uk": [51.5074, -0.1278],
}

def fetch_rss(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            xml_data = response.read()
            root = ET.fromstring(xml_data)
            items = []
            for item in root.findall('./channel/item'):
                items.append({
                    "title": item.find('title').text if item.find('title') is not None else "",
                    "link": item.find('link').text if item.find('link') is not None else "",
                    "pubDate": item.find('pubDate').text if item.find('pubDate') is not None else ""
                })
            return items
    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
        return []

def scrape_osint_map_data():
    feeds = [
        "https://www.bleepingcomputer.com/feed/",
        "https://feeds.feedburner.com/TheHackersNews"
    ]
    
    articles = []
    for f in feeds:
        articles.extend(fetch_rss(f))
        
    vectors = []
    agents_map = {}
    vector_id = 1
    
    for item in articles:
        text = item["title"].lower()
        
        origin = None
        origin_name = "Unknown Threat Actor"
        target = None
        target_name = "Global Infrastructure"
        
        # Detect Origin
        for kw in ["russia", "russian", "china", "chinese", "iran", "iranian", "north korea", "dprk", "us ", "usa ", "uk "]:
            if kw in text:
                origin = GEO_MAPPING[kw.strip()]
                origin_name = kw.strip().title()
                break
                
        # Detect Target
        for kw in ["kenya", "nairobi", "mombasa", "uganda", "tanzania", "east africa", "middle east", "europe"]:
            if kw in text:
                target = GEO_MAPPING[kw]
                target_name = kw.title()
                break
                
        # Smart OSINT routing: If news mentions origin but no target, assume it's a global campaign hitting Kenya
        if origin and not target:
            target = GEO_MAPPING["kenya"]
            target_name = "Kenya (Global Campaign Target)"
            
        # If target mentioned but no origin, assume darkweb/eastern origin
        if target and not origin:
            origin = GEO_MAPPING["russia"]
            origin_name = "Unattributed Eastern Origin"
            
        # If neither is found, check if it's a critical keyword to include it anyway targeting Kenya
        if not origin and not target:
            if any(k in text for k in ["ransomware", "apt", "botnet", "cve-", "zero-day", "malware", "phishing"]):
                origin = GEO_MAPPING["china"]
                origin_name = "Unattributed APT"
                target = GEO_MAPPING["kenya"]
                target_name = "Kenya (Active Threat Surface)"
            else:
                continue 
                
        if target_name not in agents_map:
            agents_map[target_name] = {
                "id": len(agents_map) + 1,
                "name": target_name,
                "coords": target,
                "status": "Critical" if "ransomware" in text or "apt" in text else "Elevated",
                "alerts": 0,
                "sector": "OSINT Targeted Sector",
                "threats": []
            }
            
        agents_map[target_name]["alerts"] += 1
        agents_map[target_name]["threats"].append({
            "title": item["title"],
            "link": item["link"]
        })
        
        vectors.append({
            "id": vector_id,
            "origin": origin,
            "originName": origin_name,
            "target": target,
            "type": item["title"],
            "link": item["link"]
        })
        vector_id += 1
        
    return {
        "agents": list(agents_map.values()),
        "vectors": vectors[:25]
    }
