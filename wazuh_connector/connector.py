import os
import time
import json
import logging
import requests
import urllib3
import subprocess
from datetime import datetime, timezone, timedelta
from confluent_kafka import Producer

# Disable insecure request warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("wazuh-connector")

# ── Environment variables ─────────────────────────────────────────────────────
WAZUH_API_URL        = os.getenv("WAZUH_API_URL",   "https://127.0.0.1:55000")
WAZUH_JWT_TOKEN      = os.getenv("WAZUH_JWT_TOKEN", "")
WAZUH_INDEXER_HOST   = os.getenv("WAZUH_INDEXER_HOST", "https://127.0.0.1:9201")
WAZUH_INDEXER_USER   = os.getenv("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASS   = os.getenv("WAZUH_INDEXER_PASS", "")
WAZUH_ALERTS_ENABLED = os.getenv("WAZUH_ALERTS_ENABLED", "true").lower() == "true"
WAZUH_ALERT_SOURCE   = os.getenv("WAZUH_ALERT_SOURCE", "ssh_file")
WAZUH_SSH_USER       = os.getenv("WAZUH_SSH_USER", "ubuntu")
WAZUH_SSH_HOST       = os.getenv("WAZUH_SSH_HOST", "127.0.0.1")
WAZUH_SSH_KEY        = os.getenv("WAZUH_SSH_KEY", "/app/dc_siem.pem")
WAZUH_ALERTS_FILE    = os.getenv("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
WAZUH_ARCHIVES_FILE  = os.getenv("WAZUH_ARCHIVES_FILE", "/var/ossec/logs/archives/archives.json")
WAZUH_ALERT_TAIL_LINES = int(os.getenv("WAZUH_ALERT_TAIL_LINES", "2000"))
POLL_INTERVAL        = int(os.getenv("POLL_INTERVAL", "30"))
MANAGER_LOG_LIMIT    = int(os.getenv("MANAGER_LOG_LIMIT", "100"))
ALERT_FETCH_MINUTES  = int(os.getenv("ALERT_FETCH_MINUTES", "2"))
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

WAZUH_API_USER       = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS       = os.getenv("WAZUH_API_PASS", "")

HEADERS = {}
if WAZUH_JWT_TOKEN:
    HEADERS["Authorization"] = f"Bearer {WAZUH_JWT_TOKEN}"

def get_wazuh_token():
    if not WAZUH_API_PASS:
        logger.warning("No WAZUH_API_PASS configured. Cannot generate API token.")
        return False
        
    url = f"{WAZUH_API_URL}/security/user/authenticate"
    try:
        resp = requests.post(url, auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=False, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        token = data.get("data", {}).get("token")
        if token:
            HEADERS["Authorization"] = f"Bearer {token}"
            return True
        logger.error("Wazuh API authentication failed: No token in response")
    except Exception as exc:
        logger.error("Wazuh API authentication failed: %s", exc)
    return False

def wazuh_get(path: str, params: dict = None):
    """GET from Wazuh REST API, return data dict or None."""
    url = f"{WAZUH_API_URL}{path}"
    
    if "Authorization" not in HEADERS:
        if not get_wazuh_token():
            return None

    try:
        resp = requests.get(url, headers=HEADERS, params=params, verify=False, timeout=15)
        
        # Refresh token on 401 Unauthorized
        if resp.status_code == 401:
            logger.info("Wazuh API token expired. Refreshing...")
            if get_wazuh_token():
                resp = requests.get(url, headers=HEADERS, params=params, verify=False, timeout=15)
            else:
                return None
                
        resp.raise_for_status()
        data = resp.json()
        if data.get("error") == 0:
            return data.get("data", {})
        logger.warning("Wazuh API error on %s: %s", path, data)
    except Exception as exc:
        logger.error("Wazuh GET %s failed: %s", path, exc)
    return None


def get_manager_logs(limit: int = 100):
    """Pull manager-level logs from the Wazuh REST API."""
    data = wazuh_get("/manager/logs", {"limit": limit, "offset": 0})
    return data.get("affected_items", []) if data else []


def get_active_agents():
    """Return list of active agent dicts (excludes manager id=000)."""
    data = wazuh_get("/agents", {"status": "active", "limit": 500})
    if not data:
        return []
    return [a for a in data.get("affected_items", []) if a.get("id") != "000"]


def fetch_wazuh_alerts(indexer_url: str, user: str, pwd: str,
                       minutes_back: int = 2, size: int = 500):
    if not pwd:
        logger.warning("Skipping Wazuh indexer fetch: WAZUH_INDEXER_PASS is not configured.")
        return []

    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes_back)).isoformat()
    query = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "range": {
                "timestamp": {"gte": since}
            }
        }
    }
    try:
        resp = requests.post(
            f"{indexer_url}/wazuh-alerts-*/_search",
            auth=(user, pwd),
            json=query,
            verify=False,
            timeout=20
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]
    except Exception as exc:
        logger.warning("Wazuh indexer fetch failed: %s", exc)
        return []


def _parse_wazuh_ts(value: str) -> datetime | None:
    if not value:
        return None
    try:
        if len(value) >= 5 and value[-5] in ("+", "-") and value[-3] != ":":
            value = f"{value[:-2]}:{value[-2:]}"
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def fetch_wazuh_logs_from_ssh(file_path: str, minutes_back: int = 2) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes_back)
    remote = f"{WAZUH_SSH_USER}@{WAZUH_SSH_HOST}"
    cmd = [
        "ssh",
        "-i", WAZUH_SSH_KEY,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=15",
        remote,
        f"sudo tail -n {WAZUH_ALERT_TAIL_LINES} {file_path}",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=True)
    except Exception as exc:
        logger.warning("Wazuh SSH alert fetch failed: %s", exc)
        return []

    alerts: list[dict] = []
    for line in proc.stdout.splitlines():
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = _parse_wazuh_ts(alert.get("timestamp", ""))
        if ts is None or ts >= since:
            alerts.append(alert)
    return alerts


def build_manager_doc(entry: dict) -> dict:
    level = entry.get("level", "info")
    
    return {
        "@timestamp":        datetime.now(timezone.utc).isoformat(),
        "ingested_at":       datetime.now(timezone.utc).isoformat(),
        "source":            "wazuh_manager",
        "connector":         "wazuh",
        "agent_id":          "000",
        "agent_name":        "wazuh-manager",
        "event_type":        "wazuh_manager_log",
        "src_ip":            None,
        "dst_ip":            None,
        "src_port":          0,
        "dst_port":          0,
        "protocol":          "other",
        "bytes":             0,
        "threat_category":   "normal" if level == "info" else "anomalous",
        "wazuh_level":       level,
        "wazuh_description": entry.get("description", ""),
        "rule_id":           None,
        "rule_name":         None,
        "severity":          level,
        "mitre_ids":         [],
        "mitre_tactics":     [],
        "mitre_techniques":  [],
        "raw":               entry
    }


def build_alert_doc(alert: dict, agent_map: dict) -> dict:
    agent     = alert.get("agent", {})
    rule      = alert.get("rule", {})
    data      = alert.get("data", {})
    
    import ipaddress
    def get_valid_ip(val):
        try:
            if val:
                ipaddress.ip_address(val)
                return val
        except ValueError:
            pass
        return None

    src_ip = get_valid_ip(data.get("srcip"))
    dst_ip = get_valid_ip(data.get("destip")) or get_valid_ip(data.get("dstip"))

    agent_id   = agent.get("id", "")
    agent_info = agent_map.get(agent_id, {})

    rule_level = int(rule.get("level", 0))
    if rule_level >= 12:
        threat_cat = "anomalous"
    elif rule_level >= 7:
        threat_cat = "suspicious"
    else:
        threat_cat = "normal"

    mitre      = rule.get("mitre", {})
    mitre_ids  = mitre.get("id", [])
    mitre_tacs = mitre.get("tactic", [])
    mitre_tech = mitre.get("technique", [])

    groups = rule.get("groups", [])
    event_type = "wazuh_alert"
    for g in groups:
        if g in ("syscheck", "rootcheck", "sca", "localfile"):
            event_type = g
            break
    if event_type == "wazuh_alert" and groups:
        event_type = groups[0]

    return {
        "@timestamp":        alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "ingested_at":       datetime.now(timezone.utc).isoformat(),
        "source":            "wazuh_agent",
        "connector":         "wazuh",
        "agent_id":          agent_id,
        "agent_name":        agent.get("name", ""),
        "event_type":        event_type,
        "src_ip":            src_ip,
        "dst_ip":            dst_ip,
        "src_port":          int(data.get("srcport", 0)),
        "dst_port":          int(data.get("destport") or data.get("dstport", 0)),
        "protocol":          str(data.get("protocol", "other")),
        "bytes":             int(data.get("bytes") or data.get("srcbytes", 0)),
        "threat_category":   threat_cat,
        "wazuh_level":       str(rule_level),
        "wazuh_description": str(rule.get("description", "")),
        "rule_id":           str(rule.get("id", "")),
        "rule_name":         str(rule.get("description", "")),
        "severity":          str(rule_level),
        "mitre_ids":         mitre_ids if isinstance(mitre_ids, list) else [mitre_ids],
        "mitre_tactics":     mitre_tacs if isinstance(mitre_tacs, list) else [mitre_tacs],
        "mitre_techniques":  mitre_tech if isinstance(mitre_tech, list) else [mitre_tech],
        "raw":               alert
    }


def make_alert_id(alert: dict) -> str:
    return f"{alert.get('id','')}-{alert.get('timestamp','')}"


def make_log_id(entry: dict) -> int:
    return hash(f"{entry.get('timestamp','')}-{entry.get('description','')}")


def delivery_report(err, msg):
    if err is not None:
        logger.error(f"Message delivery failed: {err}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    logger.info("Starting Wazuh Connector v2 (agent-alert mode)…")
    logger.info("Wazuh API     : %s", WAZUH_API_URL)
    logger.info("Wazuh Indexer : %s", WAZUH_INDEXER_HOST)
    logger.info(
        "Wazuh alerts  : %s via %s",
        "enabled" if WAZUH_ALERTS_ENABLED else "disabled",
        WAZUH_ALERT_SOURCE,
    )

    try:
        resp = requests.get(
            f"{WAZUH_API_URL}/agents",
            headers=HEADERS,
            params={"limit": 1},
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        total_agents = resp.json().get("data", {}).get("total_affected_items", "?")
        logger.info("Authenticated with Wazuh API. total_agents=%s", total_agents)
    except Exception as exc:
        logger.warning("Wazuh API auth check failed (token may still work): %s", exc)

    producer = Producer({
        'bootstrap.servers': KAFKA_BOOTSTRAP_SERVERS,
        'acks': 1,
        'linger.ms': 50,
        'batch.num.messages': 500
    })

    seen_log_ids:   set = set()
    seen_alert_ids: set = set()
    cycle = 0

    while True:
        cycle += 1
        total_new = 0

        # ── 1. Manager logs via REST API ─────────────────────────────────────
        for entry in get_manager_logs(limit=MANAGER_LOG_LIMIT):
            lid = make_log_id(entry)
            if lid not in seen_log_ids:
                try:
                    doc = build_manager_doc(entry)
                    producer.produce(
                        'soc.logs.wazuh',
                        key=doc['agent_id'].encode('utf-8') if doc['agent_id'] else b"",
                        value=json.dumps(doc).encode('utf-8'),
                        callback=delivery_report
                    )
                    seen_log_ids.add(lid)
                    total_new += 1
                except Exception as exc:
                    logger.error("Manager doc build/produce failed: %s", exc)

        # ── 2. Agent alerts via Wazuh OpenSearch Indexer ─────────────────────
        agents     = get_active_agents()
        agent_map  = {a["id"]: a for a in agents}

        alerts = []
        if WAZUH_ALERTS_ENABLED:
            if WAZUH_ALERT_SOURCE == "indexer":
                alerts = fetch_wazuh_alerts(
                    WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS,
                    minutes_back=ALERT_FETCH_MINUTES
                )
            elif WAZUH_ALERT_SOURCE == "ssh_file":
                alerts = fetch_wazuh_logs_from_ssh(WAZUH_ALERTS_FILE, minutes_back=ALERT_FETCH_MINUTES)
                archives = fetch_wazuh_logs_from_ssh(WAZUH_ARCHIVES_FILE, minutes_back=ALERT_FETCH_MINUTES)
                alerts.extend(archives)

        agent_alert_counts: dict = {}
        for alert in alerts:
            aid = make_alert_id(alert)
            if aid not in seen_alert_ids:
                try:
                    doc = build_alert_doc(alert, agent_map)
                    producer.produce(
                        'soc.logs.wazuh',
                        key=doc['agent_id'].encode('utf-8') if doc['agent_id'] else b"",
                        value=json.dumps(doc).encode('utf-8'),
                        callback=delivery_report
                    )
                    seen_alert_ids.add(aid)
                    total_new += 1
                    aname = doc.get("agent_name", "?")
                    agent_alert_counts[aname] = agent_alert_counts.get(aname, 0) + 1
                except Exception as exc:
                    logger.error("Alert doc build/produce failed: %s", exc)

        producer.poll(0)

        if agent_alert_counts:
            for aname, count in sorted(agent_alert_counts.items(),
                                       key=lambda x: -x[1])[:5]:
                logger.info("  Agent %-20s → %d alert(s)", aname, count)

        logger.info(
            "Cycle %d | manager_logs+alerts → %d new docs | active_agents=%d",
            cycle, total_new, len(agents)
        )

        if len(seen_log_ids) > 10_000:
            seen_log_ids.clear()
        if len(seen_alert_ids) > 50_000:
            seen_alert_ids.clear()

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
