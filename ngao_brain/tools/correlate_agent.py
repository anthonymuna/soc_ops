# tools/correlate_agent.py
import os
import json
from datetime import datetime, timezone, timedelta
from collections import Counter
from elasticsearch import Elasticsearch
from langchain.tools import tool

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
es = Elasticsearch(ES_HOST)

@tool
def correlate_agent_history(agent_name: str) -> str:
    """
    Get the full 24-hour event history for a specific Wazuh agent.
    Accepts: agent_name (string).
    Returns: total_events, unique_event_types, attack_pattern (list of event_types in chronological order), most_targeted_ports, worst_severity.
    """
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=24)).isoformat()
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"ml_detected_at": {"gte": since}}},
                    {"term": {"agent_name.keyword": agent_name}}
                ]
            }
        },
        "size": 500,
        "sort": [{"ml_detected_at": {"order": "asc"}}]
    }
    
    try:
        resp = es.search(index="syndicate4-ml-alerts", body=query)
        hits = resp.get("hits", {}).get("hits", [])
        
        total_events = len(hits)
        event_types = []
        targeted_ports = []
        severities = []
        
        # Chronological list of event types for the attack pattern
        attack_pattern = []
        
        for hit in hits:
            source = hit.get("_source", {})
            event_type = source.get("event_type", "unknown")
            event_types.append(event_type)
            attack_pattern.append(event_type)
            
            # Extract port if present in raw log or description
            dst_port = source.get("dst_port")
            if dst_port is not None:
                targeted_ports.append(str(dst_port))
                
            severity = source.get("ml_severity", "low").lower()
            severities.append(severity)
            
        unique_event_types = list(set(event_types))
        
        # Calculate target port frequencies
        port_counts = Counter(targeted_ports)
        most_targeted_ports = [port for port, _ in port_counts.most_common(3)]
        
        # Calculate worst severity
        severity_hierarchy = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        worst_sev_num = 0
        worst_severity = "low"
        
        for sev in severities:
            num = severity_hierarchy.get(sev, 1)
            if num > worst_sev_num:
                worst_sev_num = num
                worst_severity = sev
                
        return json.dumps({
            "total_events": total_events,
            "unique_event_types": unique_event_types,
            "attack_pattern": attack_pattern[-20:], # Return last 20 events chronologically
            "most_targeted_ports": most_targeted_ports,
            "worst_severity": worst_severity
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Failed to query agent history: {str(e)}"
        })
