# tools/execute_action.py
import os
import json
import urllib.parse as urlparse
import psycopg2
import requests
from langchain.tools import tool

DATABASE_URL = os.getenv("DATABASE_URL", "postgres://syndicate4:changeme@postgres:5432/syndicate4")
RESPONDER_URL = os.getenv("RESPONDER_URL", "http://responder:8001")

@tool
def execute_approved_action(pending_action_id: str) -> str:
    """
    Execute a previously approved pending action. Only call this when the analyst has explicitly
    approved the action via the dashboard.
    Accepts: pending_action_id (string, which can be the database integer ID or string triage_id).
    Calls the auto-responder service to block the IP via pfSense.
    Returns: JSON response indicating success status and result message.
    """
    url = urlparse.urlparse(DATABASE_URL)
    dbname = url.path[1:]
    user = url.username
    password = url.password
    host = url.hostname
    port = url.port
    
    conn = None
    ip_address = None
    reason = None
    severity = None
    db_id = None
    triage_id = None
    
    try:
        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )
        cur = conn.cursor()
        
        # Try finding by numeric id or triage_id string
        try:
            val_id = int(pending_action_id)
            cur.execute("SELECT id, ip_address, reason, severity, triage_id FROM alerts_pendingaction WHERE id = %s", (val_id,))
        except ValueError:
            cur.execute("SELECT id, ip_address, reason, severity, triage_id FROM alerts_pendingaction WHERE triage_id = %s", (pending_action_id,))
            
        row = cur.fetchone()
        if not row:
            return json.dumps({
                "success": False,
                "message": f"Pending action with ID '{pending_action_id}' not found in database."
            })
            
        db_id, ip_address, reason, severity, triage_id = row
        
        # Call responder service to block the IP
        responder_endpoint = f"{RESPONDER_URL.rstrip('/')}/blocks"
        payload = {
            "ip": ip_address,
            "reason": reason,
            "severity": severity
        }
        
        resp = requests.post(responder_endpoint, json=payload, timeout=10)
        if resp.status_code == 200:
            resp_data = resp.json()
            success = resp_data.get("success", True)
            msg = resp_data.get("message", "Block applied")
            
            if success:
                # Update status in database to 'executed'
                cur.execute("UPDATE alerts_pendingaction SET status = 'executed', reviewed_at = NOW() WHERE id = %s", (db_id,))
                conn.commit()
                
            return json.dumps({
                "success": success,
                "message": f"Responder response: {msg}",
                "status": "executed" if success else "failed"
            })
        else:
            return json.dumps({
                "success": False,
                "message": f"Auto-responder service returned status {resp.status_code}: {resp.text}"
            })
            
    except Exception as e:
        if conn:
            conn.rollback()
        return json.dumps({
            "success": False,
            "message": f"Failed to execute approved action: {str(e)}"
        })
    finally:
        if conn:
            conn.close()
