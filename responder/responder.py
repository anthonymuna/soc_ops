"""
Syndicate4 Auto-Responder.
Polls syndicate4-ml-alerts, auto-blocks high-severity src_ips via pfSense API.
DRY_RUN=true logs would-be blocks without calling pfSense — default for POC.
"""

import ipaddress
import logging
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone

import requests
import urllib3
from elasticsearch import Elasticsearch, NotFoundError
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("responder")

ES_HOST          = os.getenv("ES_HOST", "http://elasticsearch:9200")
PFSENSE_URL      = os.getenv("PFSENSE_URL", "")
PFSENSE_API_KEY  = os.getenv("PFSENSE_API_KEY", "")
ALIAS_NAME       = os.getenv("PFSENSE_ALIAS", "syndicate4_blocklist")
BLOCK_SEVERITIES = set(os.getenv("BLOCK_SEVERITIES", "critical,high").split(","))
POLL_INTERVAL    = int(os.getenv("POLL_INTERVAL", "10"))
DRY_RUN          = os.getenv("DRY_RUN", "true").lower() == "true"
QWEN_API_URL     = os.getenv("QWEN_API_URL", "https://localhost/v1").rstrip('/')
QWEN_API_KEY     = os.getenv("QWEN_API_KEY", "")

ALERT_INDEX = "syndicate4-ml-alerts"
BLOCK_INDEX = "syndicate4-blocks"

# Private ranges + any custom CIDRs from NEVER_BLOCK env (comma-separated)
_NEVER_BLOCK_NETS: list[ipaddress.IPv4Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
]
for _cidr in os.getenv("NEVER_BLOCK", "").split(","):
    _cidr = _cidr.strip()
    if _cidr:
        try:
            _NEVER_BLOCK_NETS.append(ipaddress.ip_network(_cidr, strict=False))
        except ValueError:
            logger.warning(f"Invalid NEVER_BLOCK entry ignored: {_cidr}")

es = Elasticsearch(ES_HOST, request_timeout=30)

_blocked_ips: set[str] = set()
_block_log: list[dict] = []
_stats = {
    "checked": 0,
    "blocked": 0,
    "skipped_allowlist": 0,
    "skipped_duplicate": 0,
    "pfsense_errors": 0,
}
_last_alert_time: str | None = None


def _is_blockable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not any(addr in net for net in _NEVER_BLOCK_NETS)
    except ValueError:
        return False


def _call_pfsense(ip: str, reason: str) -> bool:
    if not PFSENSE_URL or not PFSENSE_API_KEY:
        logger.warning(f"pfSense not configured — skipping block for {ip}")
        return False
    try:
        resp = requests.post(
            f"{PFSENSE_URL}/api/v1/firewall/alias/entry",
            headers={
                "Authorization": PFSENSE_API_KEY,
                "Content-Type": "application/json",
            },
            json={"name": ALIAS_NAME, "address": ip, "detail": reason[:255]},
            timeout=10,
            verify=False,
        )
        if resp.status_code in (200, 201):
            logger.info(f"Blocked {ip} in pfSense alias '{ALIAS_NAME}'")
            return True
        logger.warning(f"pfSense API returned {resp.status_code}: {resp.text[:200]}")
        return False
    except Exception as exc:
        logger.error(f"pfSense API call failed: {exc}")
        return False


def _record_block(ip: str, alert: dict, pfsense_ok: bool) -> None:
    record = {
        "blocked_ip": ip,
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "ml_severity": alert.get("ml_severity"),
        "ml_rf_class": alert.get("ml_rf_class"),
        "ml_rf_confidence": alert.get("ml_rf_confidence"),
        "ml_explanation": alert.get("ml_explanation"),
        "src_port": alert.get("src_port"),
        "dst_port": alert.get("dst_port"),
        "event_type": alert.get("event_type"),
        "pfsense_blocked": pfsense_ok,
        "dry_run": DRY_RUN,
    }
    _block_log.insert(0, record)
    if len(_block_log) > 500:
        _block_log.pop()
    try:
        es.index(index=BLOCK_INDEX, document=record)
    except Exception as exc:
        logger.warning(f"Block record ES write failed: {exc}")


def _fetch_new_alerts() -> list[dict]:
    global _last_alert_time
    since = _last_alert_time or (
        datetime.now(timezone.utc) - timedelta(minutes=2)
    ).isoformat()
    try:
        resp = es.search(
            index=ALERT_INDEX,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"ml_detected_at": {"gt": since}}},
                            {"terms": {"ml_severity": list(BLOCK_SEVERITIES)}},
                        ]
                    }
                },
                "size": 100,
                "sort": [{"ml_detected_at": {"order": "asc"}}],
            },
        )
        hits = [h["_source"] for h in resp["hits"]["hits"]]
        if hits:
            _last_alert_time = hits[-1]["ml_detected_at"]
        return hits
    except NotFoundError:
        return []
    except Exception as exc:
        logger.warning(f"ES fetch error: {exc}")
        return []


def _qwen_should_block(alert: dict) -> bool:
    try:
        url = f"{QWEN_API_URL}/chat/completions"
        headers = {
            "Authorization": f"Bearer {QWEN_API_KEY}"
        }
        
        system_prompt = (
            "You are an automated response gate. Decide whether to block this IP. "
            "Return ONLY valid JSON in the format: {\"block\": true/false, \"reason\": \"...\"}"
        )
        
        prompt_data = {
            "src_ip": alert.get("src_ip"),
            "attack_class": alert.get("ml_rf_class"),
            "severity": alert.get("ml_severity"),
            "ml_explanation": alert.get("ml_explanation"),
            "detection_method": alert.get("detection_method"),
            "ml_if_score": alert.get("ml_if_score")
        }
        
        payload = {
            "model": "Qwen/Qwen2.5-3B-Instruct",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(prompt_data)}
            ],
            "max_tokens": 100
        }
        
        resp = requests.post(url, headers=headers, json=payload, verify=False, timeout=8)
        resp.raise_for_status()
        
        content = resp.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        
        if content.startswith("```json"):
            content = content[7:]
        elif content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
            
        data = json.loads(content.strip())
        block_decision = bool(data.get("block", True))
        reason = data.get("reason", "No reason provided")
        
        logger.info(f"Qwen decision for {alert.get('src_ip')}: block={block_decision}, reason={reason}")
        return block_decision
        
    except Exception as e:
        logger.warning(f"Qwen unreachable or failed parsing, failing open (block=True): {e}")
        return True


def _process_alerts() -> None:
    for alert in _fetch_new_alerts():
        _stats["checked"] += 1
        ip = str(alert.get("src_ip", "")).strip()
        if not ip or ip in ("", "unknown", "0.0.0.0"):
            continue

        if not _is_blockable(ip):
            _stats["skipped_allowlist"] += 1
            logger.debug(f"Allowlist skip: {ip}")
            continue

        if ip in _blocked_ips:
            _stats["skipped_duplicate"] += 1
            continue

        severity = alert.get("ml_severity", "")
        rf_class = alert.get("ml_rf_class", "unknown")
        rf_conf = float(alert.get("ml_rf_confidence") or 0)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        reason = f"syndicate4:{severity}:{rf_class}:{rf_conf:.0%}:{ts}"

        if not _qwen_should_block(alert):
            logger.info(f"Qwen vetoed block action for {ip}")
            continue

        if DRY_RUN:
            logger.info(f"[DRY RUN] Would block {ip} — {reason}")
            _blocked_ips.add(ip)
            _stats["blocked"] += 1
            _record_block(ip, alert, pfsense_ok=False)
        else:
            ok = _call_pfsense(ip, reason)
            if ok:
                _blocked_ips.add(ip)
                _stats["blocked"] += 1
            else:
                _stats["pfsense_errors"] += 1
            _record_block(ip, alert, pfsense_ok=ok)


def _poll_loop() -> None:
    while True:
        try:
            _process_alerts()
        except Exception as exc:
            logger.error(f"Poll loop error: {exc}")
        time.sleep(POLL_INTERVAL)


app = FastAPI(title="Syndicate4 Auto-Responder", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    t = threading.Thread(target=_poll_loop, daemon=True)
    t.start()
    logger.info(
        f"Responder started | poll={POLL_INTERVAL}s | dry_run={DRY_RUN} "
        f"| severities={BLOCK_SEVERITIES} | pfsense={'configured' if PFSENSE_URL else 'NOT configured'}"
    )


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "dry_run": DRY_RUN,
        "pfsense_configured": bool(PFSENSE_URL and PFSENSE_API_KEY),
        "pfsense_url": PFSENSE_URL or None,
        "alias": ALIAS_NAME,
        "block_severities": list(BLOCK_SEVERITIES),
        "poll_interval_seconds": POLL_INTERVAL,
        "blocked_count": len(_blocked_ips),
        "stats": _stats,
    }


@app.get("/blocks")
def get_blocks(limit: int = 50) -> dict:
    return {
        "total": len(_blocked_ips),
        "blocked_ips": sorted(_blocked_ips),
        "recent": _block_log[:limit],
    }


class BlockRequest(BaseModel):
    ip: str
    reason: str
    severity: str | None = None


@app.post("/blocks")
def post_block(req: BlockRequest) -> dict:
    ip = req.ip.strip()
    if not ip or ip in ("unknown", "0.0.0.0"):
        return {"success": False, "message": f"Invalid IP address: '{ip}'"}

    if not _is_blockable(ip):
        _stats["skipped_allowlist"] += 1
        logger.info(f"Programmatic block skipped for allowlisted/private IP: {ip}")
        return {"success": False, "message": f"IP {ip} is in the allowlist/private subnet and cannot be blocked"}

    if ip in _blocked_ips:
        _stats["skipped_duplicate"] += 1
        logger.info(f"Programmatic block skipped for already blocked IP: {ip}")
        return {"success": True, "message": f"IP {ip} is already blocked"}

    # Proceed to block
    severity = req.severity or "high"
    reason = req.reason or f"programmatic block at {datetime.now(timezone.utc).isoformat()}"
    alert_dummy = {
        "ml_severity": severity,
        "ml_rf_class": "manual_triage",
        "ml_rf_confidence": 1.0,
        "ml_explanation": reason,
        "src_port": None,
        "dst_port": None,
        "event_type": "programmatic_block"
    }

    if DRY_RUN:
        logger.info(f"[DRY RUN] Programmatic block would block {ip} — {reason}")
        _blocked_ips.add(ip)
        _stats["blocked"] += 1
        _record_block(ip, alert_dummy, pfsense_ok=False)
        return {"success": True, "message": f"[DRY RUN] Would block {ip} — {reason}"}
    else:
        ok = _call_pfsense(ip, reason)
        if ok:
            _blocked_ips.add(ip)
            _stats["blocked"] += 1
            _record_block(ip, alert_dummy, pfsense_ok=ok)
            return {"success": True, "message": f"Blocked {ip} via pfSense"}
        else:
            _stats["pfsense_errors"] += 1
            _record_block(ip, alert_dummy, pfsense_ok=ok)
            return {"success": False, "message": f"Failed to block {ip} via pfSense"}


@app.delete("/blocks/{ip}")
def unblock_ip(ip: str) -> dict:
    _blocked_ips.discard(ip)
    return {
        "unblocked": ip,
        "note": "removed from local tracking only — also remove from pfSense alias manually",
    }

