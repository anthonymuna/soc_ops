# tools/propose_block.py
import os
import json
import urllib.parse as urlparse
import psycopg2
from langchain.tools import tool

DATABASE_URL = os.getenv("DATABASE_URL", "postgres://syndicate4:changeme@postgres:5432/syndicate4")

@tool
def propose_block(
    ip: str,
    reason: str,
    severity: str,
    triage_id: str,
    incident_summary: str = "",
    attack_pattern: str = "",
    confidence: int = 80,
    recommended_action: str = "block",
    mitre_techniques_json: str = "[]",
    agent_name: str = "",
    abuseipdb_score: int = 0
) -> str:
    """
    Propose blocking an IP address. This does NOT execute the block — it creates a pending action
    in the PostgreSQL database that requires analyst approval from the SOC dashboard.
    Accepts:
      ip (string)
      reason (string)
      severity (string)
      triage_id (string)
      incident_summary (string, optional)
      attack_pattern (string, optional)
      confidence (int, optional)
      recommended_action (string, optional)
      mitre_techniques_json (JSON string list, optional, e.g., '["T1110"]')
      agent_name (string, optional)
      abuseipdb_score (int, optional)
    Returns: JSON response containing status and pending_action_id.
    """
    try:
        mitre_list = json.loads(mitre_techniques_json)
    except Exception:
        mitre_list = []
        
    url = urlparse.urlparse(DATABASE_URL)
    dbname = url.path[1:]
    user = url.username
    password = url.password
    host = url.hostname
    port = url.port
    
    conn = None
    try:
        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )
        cur = conn.cursor()
        
        # Check if triage_id already exists to prevent duplicate proposals
        cur.execute("SELECT id, status FROM alerts_pendingaction WHERE triage_id = %s", (triage_id,))
        existing = cur.fetchone()
        if existing:
            return json.dumps({
                "pending_action_id": existing[0],
                "status": existing[1],
                "note": "A proposal with this triage_id already exists."
            })
            
        # Insert new pending action
        insert_query = """
            INSERT INTO alerts_pendingaction (
                triage_id, ip_address, reason, severity, incident_summary,
                attack_pattern, confidence, recommended_action, status,
                created_at, mitre_techniques, agent_name, abuseipdb_score
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s)
            RETURNING id;
        """
        
        cur.execute(insert_query, (
            triage_id,
            ip,
            reason,
            severity,
            incident_summary or reason,
            attack_pattern,
            confidence,
            recommended_action,
            "awaiting_approval",
            json.dumps(mitre_list),
            agent_name,
            abuseipdb_score
        ))
        
        pending_action_id = cur.fetchone()[0]
        conn.commit()
        
        return json.dumps({
            "pending_action_id": pending_action_id,
            "status": "awaiting_approval",
            "message": f"Successfully proposed block for IP {ip} (ID: {pending_action_id})"
        })
    except Exception as e:
        if conn:
            conn.rollback()
        return json.dumps({
            "status": "error",
            "message": f"Failed to insert pending action: {str(e)}"
        })
    finally:
        if conn:
            conn.close()
