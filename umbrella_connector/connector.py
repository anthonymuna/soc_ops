import os
import time
import json
import logging
import requests
from requests.auth import HTTPBasicAuth
from confluent_kafka import Producer
from datetime import datetime, timezone, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("umbrella-connector")

UMBRELLA_CLIENT_ID = os.getenv("UMBRELLA_CLIENT_ID", "")
UMBRELLA_CLIENT_SECRET = os.getenv("UMBRELLA_CLIENT_SECRET", "")
UMBRELLA_ORG_ID = os.getenv("UMBRELLA_ORG_ID", "")
ALERT_FETCH_MINUTES = int(os.getenv("ALERT_FETCH_MINUTES", "5"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

access_token = None
token_expires_at = 0

def authenticate():
    global access_token, token_expires_at
    if time.time() < token_expires_at - 60:
        return True
    
    url = "https://api.umbrella.com/auth/v2/token"
    try:
        res = requests.post(
            url,
            auth=HTTPBasicAuth(UMBRELLA_CLIENT_ID, UMBRELLA_CLIENT_SECRET),
            data={"grant_type": "client_credentials"},
            timeout=10
        )
        res.raise_for_status()
        data = res.json()
        access_token = data.get("access_token")
        token_expires_at = time.time() + data.get("expires_in", 3600)
        logger.info("Successfully authenticated to Cisco Umbrella")
        return True
    except Exception as e:
        logger.error(f"Umbrella auth failed: {e}")
        return False

def fetch_activity(activity_type, start_ms, end_ms):
    if not authenticate():
        return []
    
    url = f"https://api.umbrella.com/reports/v2/activity/{activity_type}"
    params = {
        "from": start_ms,
        "to": end_ms,
        "limit": 500
    }
    headers = {"Authorization": f"Bearer {access_token}"}
    
    try:
        res = requests.get(url, headers=headers, params=params, timeout=30)
        res.raise_for_status()
        return res.json().get("data", [])
    except Exception as e:
        logger.error(f"Failed to fetch Umbrella {activity_type} logs: {e}")
        return []

def normalize(event, activity_type):
    threat_category = "normal"
    verdict = event.get('verdict', '').lower()
    action = event.get('action', '').lower()
    threatScore = event.get('threatScore', 0)
    malwareCategories = event.get('malwareCategories', [])
    categories = event.get('categories', [])
    
    security_categories = [
        "malware", "phishing", "botnet", "command and control", "ransomware"
    ]
    has_security_category = any(c.lower() in security_categories for c in categories)

    if verdict == "blocked" or action == "blocked":
        threat_category = "anomalous"
    elif threatScore >= 50 or malwareCategories:
        threat_category = "anomalous"
    elif verdict == "proxied" or has_security_category:
        threat_category = "suspicious"

    ts = event.get('timestamp')
    if ts:
        try:
            timestamp_str = datetime.fromtimestamp(ts/1000, tz=timezone.utc).isoformat()
        except Exception:
            timestamp_str = datetime.now(timezone.utc).isoformat()
    else:
        timestamp_str = datetime.now(timezone.utc).isoformat()
        
    doc = {
        "@timestamp": timestamp_str,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "source": "cisco_umbrella",
        "connector": "umbrella",
        "agent_id": None,
        "agent_name": None,
        "event_type": f"{activity_type}_event",
        "src_ip": None,
        "dst_ip": None,
        "src_port": 0,
        "dst_port": 0,
        "protocol": "other",
        "bytes": 0,
        "threat_category": threat_category,
        "wazuh_level": None,
        "wazuh_description": None,
        "rule_id": None,
        "rule_name": None,
        "severity": None,
        "mitre_ids": [],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "raw": event
    }

    if activity_type == "dns":
        doc["src_ip"] = event.get('internalIp')
        doc["dst_ip"] = event.get('externalIp')
        doc["protocol"] = event.get('queryType')
        doc["rule_name"] = event.get('domain')
    elif activity_type == "proxy":
        doc["src_ip"] = event.get('internalIp')
        doc["dst_ip"] = event.get('externalIp') or event.get('destination')
        doc["rule_name"] = event.get('destination')
    elif activity_type == "firewall":
        doc["src_ip"] = event.get('originIp')
        doc["dst_ip"] = event.get('destinationIp')
        doc["src_port"] = event.get('originPort') or 0
        doc["dst_port"] = event.get('destinationPort') or 0
        doc["protocol"] = event.get('protocol')
        
    return doc

def delivery_report(err, msg):
    if err is not None:
        logger.error(f"Message delivery failed: {err}")

def main():
    logger.info("Starting Cisco Umbrella Connector...")
    producer = Producer({
        'bootstrap.servers': KAFKA_BOOTSTRAP_SERVERS,
        'acks': 1,
        'linger.ms': 50,
        'batch.num.messages': 500
    })

    if not authenticate():
        logger.error("Initial authentication failed, continuing to loop")

    # Initialize last_seen times per activity type
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(minutes=ALERT_FETCH_MINUTES)
    last_seen = {
        "dns": int(start_time.timestamp() * 1000),
        "proxy": int(start_time.timestamp() * 1000),
        "firewall": int(start_time.timestamp() * 1000)
    }

    while True:
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        for activity_type in ["dns", "proxy", "firewall"]:
            events = fetch_activity(activity_type, last_seen[activity_type], now_ms)
            
            for event in events:
                doc = normalize(event, activity_type)
                key = doc['src_ip'] or ""
                
                try:
                    producer.produce(
                        'soc.logs.umbrella',
                        key=key.encode('utf-8'),
                        value=json.dumps(doc).encode('utf-8'),
                        callback=delivery_report
                    )
                except Exception as e:
                    logger.error(f"Kafka produce error: {e}")
            
            if events:
                last_seen[activity_type] = now_ms

        producer.poll(0)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
