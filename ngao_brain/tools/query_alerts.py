# tools/query_alerts.py
import os
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch
from langchain.tools import tool

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
es = Elasticsearch(ES_HOST)

@tool
def query_alerts(src_ip: str = None, agent_name: str = None, severity: str = None, mitre_id: str = None, event_type: str = None, minutes: int = 129600) -> str:
    """
    Query the Elasticsearch syndicate4-ml-alerts index for recent alerts.
    Accepts: src_ip (optional), agent_name (optional), severity (optional), mitre_id (optional), event_type (optional), minutes (int, default 129600).
    Returns list of alerts with fields: event_type, ml_severity, ml_rf_class, src_ip, dst_ip, agent_name, ml_detected_at, ml_explanation.
    """
    now = datetime.now(timezone.utc)
    since = (now - timedelta(minutes=minutes)).isoformat()
    
    must_clauses = [
        {"range": {"ml_detected_at": {"gte": since}}}
    ]
    
    # Ignore fallback/unknown placeholders
    ignore_vals = ("unknown", "n/a", "none", "null", "")
    
    if src_ip and src_ip.lower() not in ignore_vals:
        must_clauses.append({"term": {"src_ip.keyword": src_ip}})
    if agent_name and agent_name.lower() not in ignore_vals:
        must_clauses.append({"term": {"agent_name.keyword": agent_name}})
    if severity and severity.lower() not in ignore_vals:
        must_clauses.append({"term": {"ml_severity.keyword": severity}})
    if mitre_id and mitre_id.lower() not in ignore_vals:
        must_clauses.append({"term": {"mitre_id.keyword": mitre_id}})
    if event_type and event_type.lower() not in ignore_vals:
        must_clauses.append({"match": {"event_type": event_type}})
        
    query = {
        "query": {
            "bool": {
                "must": must_clauses
            }
        },
        "size": 50,
        "sort": [{"ml_detected_at": {"order": "desc"}}]
    }
    
    try:
        resp = es.search(index="syndicate4-ml-alerts", body=query)
        hits = resp.get("hits", {}).get("hits", [])
        
        alerts = []
        for hit in hits:
            source = hit.get("_source", {})
            alerts.append({
                "alert_id": hit.get("_id"),
                "event_type": source.get("event_type"),
                "ml_severity": source.get("ml_severity"),
                "ml_rf_class": source.get("ml_rf_class"),
                "src_ip": source.get("src_ip"),
                "dst_ip": source.get("dst_ip"),
                "agent_name": source.get("agent_name"),
                "ml_detected_at": source.get("ml_detected_at"),
                "ml_explanation": source.get("ml_explanation")
            })
            
        import json
        return json.dumps(alerts, indent=2)
    except Exception as e:
        return f"Error querying alerts from Elasticsearch: {str(e)}"
