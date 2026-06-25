import os
import time
import json
import logging
import requests
import xml.etree.ElementTree as ET
from confluent_kafka import Producer
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("fortisiem-connector")

FORTISIEM_URL = os.getenv("FORTISIEM_URL", "")
FORTISIEM_USER = os.getenv("FORTISIEM_USER", "")
FORTISIEM_PASS = os.getenv("FORTISIEM_PASS", "")
FORTISIEM_ORG = os.getenv("FORTISIEM_ORG", "super")
ALERT_FETCH_MINUTES = int(os.getenv("ALERT_FETCH_MINUTES", "2"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"

# Disable insecure request warnings
if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session = requests.Session()
session.verify = VERIFY_SSL

def authenticate():
    url = f"{FORTISIEM_URL}/phoenix/rest/query/login"
    data = {"username": f"{FORTISIEM_ORG}/{FORTISIEM_USER}", "password": FORTISIEM_PASS}
    try:
        res = session.post(url, data=data, timeout=10)
        res.raise_for_status()
        logger.info("Successfully authenticated to FortiSIEM")
        return True
    except Exception as e:
        logger.error(f"FortiSIEM auth failed: {e}")
        return False

def fetch_events():
    url = f"{FORTISIEM_URL}/phoenix/rest/query/eventQuery"
    query_xml = f"""
    <reports>
      <report>
        <timeRange type="Relative" value="-{ALERT_FETCH_MINUTES}m" />
        <selectClause>
          <select>eventId</select>
          <select>eventTime</select>
          <select>hostIpAddr</select>
          <select>destIpAddr</select>
          <select>srcPort</select>
          <select>destPort</select>
          <select>protocol</select>
          <select>eventType</select>
          <select>eventName</select>
          <select>rawEventMsg</select>
          <select>phEventCategory</select>
          <select>reptDevIpAddr</select>
          <select>severity</select>
          <select>incidentId</select>
          <select>customer</select>
          <select>phIncidentCategory</select>
          <select>attackTechnique</select>
          <select>attackTactic</select>
        </selectClause>
      </report>
    </reports>
    """
    try:
        res = session.post(url, data=query_xml, headers={'Content-Type': 'application/xml'}, timeout=30)
        if res.status_code == 401:
            logger.warning("FortiSIEM session expired. Re-authenticating...")
            if authenticate():
                res = session.post(url, data=query_xml, headers={'Content-Type': 'application/xml'}, timeout=30)
            else:
                return []
        
        res.raise_for_status()
        return parse_events(res.text)
    except Exception as e:
        logger.error(f"FortiSIEM fetch events failed: {e}")
        return []

def parse_events(xml_data):
    events = []
    try:
        root = ET.fromstring(xml_data)
        for event_node in root.findall('.//event'):
            event = {}
            for child in event_node:
                event[child.tag] = child.text
            events.append(event)
    except Exception as e:
        logger.error(f"Failed to parse FortiSIEM XML: {e}")
    return events

def normalize(event):
    severity = int(event.get('severity') or 0)
    if severity >= 9:
        threat_category = "anomalous"
    elif severity >= 5:
        threat_category = "suspicious"
    else:
        threat_category = "normal"
    
    mitre_tech = event.get('attackTechnique')
    mitre_techniques = [mitre_tech] if mitre_tech else []
    mitre_tactic = event.get('attackTactic')
    mitre_tactics = [mitre_tactic] if mitre_tactic else []

    try:
        src_port = int(event.get('srcPort') or 0)
    except ValueError:
        src_port = 0

    try:
        dst_port = int(event.get('destPort') or 0)
    except ValueError:
        dst_port = 0

    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(), # We don't have iso format from fortisiem out of the box, using ingested time
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "source": "fortisiem",
        "connector": "fortisiem",
        "agent_id": event.get('reptDevIpAddr'),
        "agent_name": event.get('eventType'),
        "event_type": event.get('eventName'),
        "src_ip": event.get('hostIpAddr'),
        "dst_ip": event.get('destIpAddr'),
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": event.get('protocol'),
        "bytes": 0,
        "threat_category": threat_category,
        "wazuh_level": None,
        "wazuh_description": None,
        "rule_id": str(event.get('eventId')),
        "rule_name": event.get('eventName'),
        "severity": str(severity),
        "mitre_ids": [],
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "raw": event
    }

def delivery_report(err, msg):
    if err is not None:
        logger.error(f"Message delivery failed: {err}")

def main():
    logger.info("Starting FortiSIEM Connector...")
    producer = Producer({
        'bootstrap.servers': KAFKA_BOOTSTRAP_SERVERS,
        'acks': 1,
        'linger.ms': 50,
        'batch.num.messages': 500
    })

    if not authenticate():
        logger.error("Initial authentication failed, continuing to loop")

    seen_event_ids = set()

    while True:
        events = fetch_events()
        for event in events:
            event_id = event.get('eventId')
            if not event_id or event_id in seen_event_ids:
                continue
            
            seen_event_ids.add(event_id)
            doc = normalize(event)
            key = doc['agent_id'] or ""
            
            try:
                producer.produce(
                    'soc.logs.fortisiem',
                    key=key.encode('utf-8'),
                    value=json.dumps(doc).encode('utf-8'),
                    callback=delivery_report
                )
            except Exception as e:
                logger.error(f"Kafka produce error: {e}")
        
        producer.poll(0)
        
        if len(seen_event_ids) > 100000:
            seen_event_ids.clear()
            
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
