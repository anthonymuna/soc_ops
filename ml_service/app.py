"""
FastAPI service: polls Elasticsearch, runs anomaly detection, writes alerts back.
Exposes REST API consumed by local dashboard.
"""

import os
import hmac
import hashlib
import secrets
import logging
import threading
import json
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from elasticsearch import Elasticsearch, NotFoundError
import time
import httpx
import schedule
from confluent_kafka import Consumer, KafkaError

from detector import AnomalyDetector
import report as report_gen

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("app")

ES_HOST        = os.getenv("ES_HOST", "http://elasticsearch:9200")
TRAIN_INTERVAL = int(os.getenv("TRAIN_INTERVAL_SECONDS", "300"))
SCAN_INTERVAL  = int(os.getenv("SCAN_INTERVAL_SECONDS", "15"))
LOG_INDEX_PATTERN = "syndicate4-logs-*"
ALERT_INDEX    = "syndicate4-ml-alerts"

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_ENABLED = os.getenv("KAFKA_ENABLED", "true").lower() == "true"

AUTH_USERNAME  = os.getenv("AUTH_USERNAME", "admin")
AUTH_PASSWORD  = os.getenv("AUTH_PASSWORD", "admin")
# In-memory token store: token -> expiry datetime
_active_tokens: dict[str, datetime] = {}
TOKEN_TTL_HOURS = 8

NOTIFY_WEBHOOK_URL = os.getenv("NOTIFY_WEBHOOK_URL", "")
FEEDBACK_INDEX = "syndicate4-feedback"

WHITELISTED_IPS = [ip.strip() for ip in os.getenv("WHITELISTED_IPS", "").split(",") if ip.strip()]

es       = Elasticsearch(ES_HOST, request_timeout=30)
detector = AnomalyDetector()
bearer   = HTTPBearer()

stats = {
    "logs_scanned": 0,
    "anomalies_detected": 0,
    "last_scan": None,
    "last_train": None,
    "scan_errors": 0,
}


# --- Auth helpers ---

class LoginRequest(BaseModel):
    username: str
    password: str

class ScanLiveRequest(BaseModel):
    logs: list[dict]

class FeedbackRequest(BaseModel):
    label: str  # e.g., 'normal' or 'dos'
    comment: str | None = None


def _verify_token(_creds: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))) -> str:
    # Intentionally bypass authentication as Django handles it at the gateway level.
    return "bypass"


def _fetch_logs(minutes_back: int = 5, size: int = 500, normal_only: bool = False) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes_back)).isoformat()
    query: dict[str, Any] = {
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": since}}}],
                "must_not": []
            }
        },
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
    }
    if normal_only:
        query["query"]["bool"]["must"].append(
            {"term": {"threat_category.keyword": "normal"}}
        )
    try:
        resp = es.search(index=LOG_INDEX_PATTERN, body=query)
        return [hit["_source"] for hit in resp["hits"]["hits"]]
    except Exception as e:
        logger.warning(f"ES fetch error: {e}")
        return []


def _write_alerts(alerts: list[dict]):
    for alert in alerts:
        src = alert.get("src_ip")
        dst = alert.get("dst_ip")
        if src in WHITELISTED_IPS or dst in WHITELISTED_IPS:
            continue
            
        try:
            aid = f"{alert.get('ml_detected_at','')}{alert.get('src_ip','')}{alert.get('event_type','')}"
            es.index(index=ALERT_INDEX, id=aid, document=alert)
        except Exception as e:
            logger.warning(f"Alert write error: {e}")


def _write_logs(logs: list[dict]):
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index_name = f"syndicate4-logs-{today}"
    for log in logs:
        try:
            es.index(index=index_name, document=log)
        except Exception as e:
            logger.warning(f"Log write error: {e}")


def run_train():
    logger.info("Training model on labeled logs + user feedback...")
    logs = _fetch_logs(minutes_back=120, size=5000, normal_only=False)
    
    feedback_logs = []
    try:
        if es.indices.exists(index=FEEDBACK_INDEX):
            resp = es.search(index=FEEDBACK_INDEX, body={"size": 1000})
            feedback_logs = [h["_source"] for h in resp["hits"]["hits"]]
            logger.info(f"Adding {len(feedback_logs)} user feedback samples to training set")
    except Exception as e:
        logger.warning(f"Feedback fetch error: {e}")

    result = detector.train(logs + feedback_logs)
    stats["last_train"] = datetime.now(timezone.utc).isoformat()
    logger.info(f"Train result: {result}")


def _send_notification(alert: dict):
    if not NOTIFY_WEBHOOK_URL:
        return
    
    try:
        payload = {
            "embeds": [{
                "title": f"🚨 {alert.get('ml_severity', 'high').upper()} Alert: {alert.get('ml_rf_class', 'Anomaly')}",
                "description": alert.get("ml_explanation", "No explanation provided"),
                "color": 15158332 if alert.get("ml_severity") == "critical" else 15105570,
                "fields": [
                    {"name": "Source IP", "value": alert.get("src_ip", "unknown"), "inline": True},
                    {"name": "Dest IP", "value": alert.get("dst_ip", "unknown"), "inline": True},
                    {"name": "Port", "value": str(alert.get("dst_port", "0")), "inline": True},
                ],
                "footer": {"text": f"NGAO SOC AI Engine • {alert.get('ml_detected_at')}"}
            }]
        }
        with httpx.Client() as client:
            client.post(NOTIFY_WEBHOOK_URL, json=payload)
    except Exception as e:
        logger.warning(f"Notification failed: {e}")


def run_scan():
    logs = _fetch_logs(minutes_back=5, size=2000)
    if not logs:
        return
    stats["logs_scanned"] += len(logs)
    stats["last_scan"] = datetime.now(timezone.utc).isoformat()
    try:
        if not detector.is_trained():
            logger.info("Model not trained yet — skipping scan")
            return
        alerts = detector.predict(logs)
        if alerts:
            filtered_alerts = [a for a in alerts if a.get("src_ip") not in WHITELISTED_IPS and a.get("dst_ip") not in WHITELISTED_IPS]
            
            stats["anomalies_detected"] += len(filtered_alerts)
            _write_alerts(filtered_alerts)
            logger.info(f"ML: {len(filtered_alerts)} anomalies (suppressed {len(alerts) - len(filtered_alerts)})")
            for alert in filtered_alerts:
                if alert.get("ml_severity") in ("critical", "high"):
                    _send_notification(alert)
    except Exception as e:
        stats["scan_errors"] += 1
        logger.error(f"Scan error: {e}")


def _kafka_consumer_thread():
    if not KAFKA_ENABLED:
        logger.info("Kafka consumer is disabled (KAFKA_ENABLED=false).")
        return
    
    conf = {
        'bootstrap.servers': KAFKA_BOOTSTRAP_SERVERS,
        'group.id': 'soc-ml-group',
        'auto.offset.reset': 'latest',
        'enable.auto.commit': True,
        'max.poll.interval.ms': 300000
    }
    
    try:
        consumer = Consumer(conf)
        consumer.subscribe(['soc.logs.wazuh', 'soc.logs.fortisiem', 'soc.logs.umbrella'])
        logger.info(f"Kafka consumer started. Subscribed to topics.")
    except Exception as e:
        logger.error(f"Failed to start Kafka consumer: {e}")
        return

    buffer = []
    last_flush = time.time()
    
    while True:
        try:
            msg = consumer.poll(timeout=1.0)
            
            if msg is not None:
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error(f"Kafka Consumer Error: {msg.error()}")
                else:
                    try:
                        doc = json.loads(msg.value().decode('utf-8'))
                        buffer.append(doc)
                    except Exception as e:
                        logger.error(f"Failed to parse Kafka message: {e}")
            
            now = time.time()
            if len(buffer) >= 100 or (buffer and now - last_flush >= 10):
                # Process buffer
                stats["logs_scanned"] += len(buffer)
                stats["last_scan"] = datetime.now(timezone.utc).isoformat()
                
                # Write to general logs index
                _write_logs(buffer)
                
                if detector.is_trained():
                    alerts = detector.predict(buffer)
                    if alerts:
                        filtered_alerts = [a for a in alerts if a.get("src_ip") not in WHITELISTED_IPS and a.get("dst_ip") not in WHITELISTED_IPS]
                        
                        stats["anomalies_detected"] += len(filtered_alerts)
                        _write_alerts(filtered_alerts)
                        logger.info(f"ML: {len(filtered_alerts)} anomalies from {len(buffer)} Kafka logs (suppressed {len(alerts) - len(filtered_alerts)})")
                        for alert in filtered_alerts:
                            if alert.get("ml_severity") in ("critical", "high"):
                                _send_notification(alert)
                else:
                    logger.info("Model not trained yet — skipping Kafka batch anomaly check")

                buffer.clear()
                last_flush = time.time()
                
        except Exception as e:
            logger.error(f"Error in Kafka consumer loop: {e}")
            time.sleep(1)


def _scheduler_thread():
    schedule.every(TRAIN_INTERVAL).seconds.do(run_train)
    schedule.every(SCAN_INTERVAL).seconds.do(run_scan)
    run_train()
    while True:
        schedule.run_pending()
        time.sleep(1)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    t_sched = threading.Thread(target=_scheduler_thread, daemon=True)
    t_sched.start()
    
    t_kafka = threading.Thread(target=_kafka_consumer_thread, daemon=True)
    t_kafka.start()
    
    logger.info(f"Scheduler and Kafka Consumer started. Train every {TRAIN_INTERVAL}s, scan every {SCAN_INTERVAL}s")
    yield


app = FastAPI(title="Syndicate4 ML Anomaly Detector", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Auth endpoints (public) ---

@app.post("/auth/login")
def login(req: LoginRequest):
    if not (hmac.compare_digest(req.username, AUTH_USERNAME) and
            hmac.compare_digest(req.password, AUTH_PASSWORD)):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_hex(32)
    _active_tokens[token] = datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL_HOURS)
    logger.info(f"Login: {req.username}")
    return {"token": token, "expires_in_hours": TOKEN_TTL_HOURS}


@app.post("/auth/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    _active_tokens.pop(credentials.credentials, None)
    return {"message": "Logged out"}


# --- Protected endpoints ---

@app.get("/health")
def health(_token: str = Depends(_verify_token)):
    return {
        "status": "ok",
        "model_trained": detector.is_trained(),
        "nsl_kdd_trained": detector.nsl_kdd_trained,
        "live_supervised": detector.live_supervised,
        "zs_classifier_ready": detector.zs_classifier.available if detector.zs_classifier else False,
        "trained_at": detector.trained_at.isoformat() if detector.trained_at else None,
        "training_samples": detector.training_samples,
        "es_connected": es.ping(),
    }


@app.get("/stats")
def get_stats(connector: str = None, _token: str = Depends(_verify_token)):
    try:
        query = {"query": {"match_all": {}}}
        if connector:
            query = {"query": {"term": {"connector.keyword": connector}}}
            
        es_logs_count = es.count(index="syndicate4-logs-*", body=query)["count"]
        es_alerts_count = es.count(index="syndicate4-ml-alerts", body=query)["count"]
        
        return {
            **stats, 
            "logs_scanned": es_logs_count,
            "anomalies_detected": es_alerts_count
        }
    except Exception as e:
        logger.warning(f"Failed to fetch stats from ES: {e}")
        # Fallback to global in-memory stats
        return {**stats, "logs_scanned": stats["logs_scanned"]}


@app.get("/alerts")
def get_alerts(limit: int = 50, minutes: int = 60, _token: str = Depends(_verify_token)):
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    try:
        resp = es.search(
            index=ALERT_INDEX,
            body={
                "query": {"range": {"ml_detected_at": {"gte": since}}},
                "size": limit,
                "sort": [{"ml_detected_at": {"order": "desc"}}],
            },
        )
        return {
            "total": resp["hits"]["total"]["value"],
            "alerts": [h["_source"] for h in resp["hits"]["hits"]],
        }
    except NotFoundError:
        return {"total": 0, "alerts": []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/alerts/{alert_id}/feedback")
def submit_feedback(alert_id: str, req: FeedbackRequest, _token: str = Depends(_verify_token)):
    logger.info(f"Feedback received for {alert_id}: {req.label}")
    try:
        feedback_doc = {
            "alert_id": alert_id,
            "label": req.label,
            "comment": req.comment,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        res = es.index(index=FEEDBACK_INDEX, document=feedback_doc)
        
        try:
            es.update(index=ALERT_INDEX, id=alert_id, body={"doc": {"human_labeled": req.label}})
        except Exception as e:
            logger.warning(f"Failed to update alert status: {e}")

        logger.info(f"Feedback indexed: {res.get('result')}")
        return {"status": "success", "id": res.get("_id")}
    except Exception as e:
        logger.error(f"Feedback failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/train")
def trigger_train(background_tasks: BackgroundTasks, _token: str = Depends(_verify_token)):
    background_tasks.add_task(run_train)
    return {"message": "Training triggered in background"}


@app.post("/scan")
def trigger_scan(background_tasks: BackgroundTasks, _token: str = Depends(_verify_token)):
    background_tasks.add_task(run_scan)
    return {"message": "Scan triggered in background"}


@app.post("/scan_live")
def scan_live(req: ScanLiveRequest):
    if not req.logs:
        return {"scanned": 0, "anomalies": 0}
    stats["logs_scanned"] += len(req.logs)
    stats["last_scan"] = datetime.now(timezone.utc).isoformat()
    try:
        _write_logs(req.logs)

        if not detector.is_trained():
            logger.info("Model not trained yet — skipping scan_live anomaly check")
            return {"scanned": len(req.logs), "anomalies": 0, "status": "not_trained"}
            
        alerts = detector.predict(req.logs)
        if alerts:
            filtered_alerts = [a for a in alerts if a.get("src_ip") not in WHITELISTED_IPS and a.get("dst_ip") not in WHITELISTED_IPS]
            
            stats["anomalies_detected"] += len(filtered_alerts)
            _write_alerts(filtered_alerts)
            logger.info(f"ML scan_live: {len(filtered_alerts)} anomalies from {len(req.logs)} logs (suppressed {len(alerts) - len(filtered_alerts)})")
            for alert in filtered_alerts:
                if alert.get("ml_severity") in ("critical", "high"):
                    _send_notification(alert)
        return {"scanned": len(req.logs), "anomalies": len(filtered_alerts) if alerts else 0}
    except Exception as e:
        stats["scan_errors"] += 1
        logger.error(f"Scan_live error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/model/status")
def model_status(_token: str = Depends(_verify_token)):
    return {
        "trained": detector.is_trained(),
        "trained_at": detector.trained_at.isoformat() if detector.trained_at else None,
        "training_samples": detector.training_samples,
        "contamination": float(os.getenv("CONTAMINATION", "0.05")),
        "scan_interval_seconds": SCAN_INTERVAL,
        "train_interval_seconds": TRAIN_INTERVAL,
    }


@app.get("/test")
def run_model_test(_token: str = Depends(_verify_token)):
    result = detector.evaluate()
    if "error" in result:
        raise HTTPException(status_code=503, detail=result["error"])
    return result


@app.get("/logs/recent")
def recent_logs(limit: int = 100, minutes: int = 10, _token: str = Depends(_verify_token)):
    logs = _fetch_logs(minutes_back=minutes, size=limit)
    return {"total": len(logs), "logs": logs}


@app.get("/report")
def get_report(hours: int = 24, _token: str = Depends(_verify_token)):
    try:
        pdf_bytes = report_gen.build_report(es, hours=hours)
        filename = f"syndicate4_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/alerts/{alert_id}/report")
def get_incident_report(alert_id: str, _token: str = Depends(_verify_token)):
    try:
        resp = es.search(index=ALERT_INDEX, body={"query": {"match": {"_id": alert_id}}})
        if not resp["hits"]["hits"]:
            resp = es.search(index=ALERT_INDEX, body={"query": {"term": {"id": alert_id}}})
            if not resp["hits"]["hits"]:
                raise HTTPException(status_code=404, detail="Alert not found")
        
        alert = resp["hits"]["hits"][0]["_source"]
        alert["_id"] = alert_id
        
        pdf_bytes = report_gen.build_incident_report(alert)
        filename = f"intel_report_{alert_id[:8]}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.error(f"Incident report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
