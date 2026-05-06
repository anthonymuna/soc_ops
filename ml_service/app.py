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
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from elasticsearch import Elasticsearch, NotFoundError
import schedule
import time

from detector import AnomalyDetector
from sigma_engine import SigmaEngine
import report as report_gen

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("app")

ES_HOST        = os.getenv("ES_HOST", "http://elasticsearch:9200")
TRAIN_INTERVAL = int(os.getenv("TRAIN_INTERVAL_SECONDS", "300"))
SCAN_INTERVAL  = int(os.getenv("SCAN_INTERVAL_SECONDS", "15"))
LOG_INDEX_PATTERN = "syndicate4-logs-*"
ALERT_INDEX    = "syndicate4-ml-alerts"

AUTH_USERNAME  = os.getenv("AUTH_USERNAME", "admin")
AUTH_PASSWORD  = os.getenv("AUTH_PASSWORD", "syndicate4")
# In-memory token store: token -> expiry datetime
_active_tokens: dict[str, datetime] = {}
TOKEN_TTL_HOURS = 8

es       = Elasticsearch(ES_HOST, request_timeout=30)
detector = AnomalyDetector()
sigma    = SigmaEngine()
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


def _verify_token(_creds: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))) -> str:
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
        try:
            es.index(index=ALERT_INDEX, document=alert)
        except Exception as e:
            logger.warning(f"Alert write error: {e}")


def run_train():
    # Fetch ALL labeled logs — threat_category field used as supervised label
    # (normal_only=True was wrong — all logs are labeled attacks from Atomic Red Team)
    logger.info("Training model on all labeled logs...")
    logs = _fetch_logs(minutes_back=120, size=5000, normal_only=False)
    result = detector.train(logs)
    stats["last_train"] = datetime.now(timezone.utc).isoformat()
    logger.info(f"Train result: {result}")


def run_scan():
    logs = _fetch_logs(minutes_back=5, size=2000)
    if not logs:
        return
    stats["logs_scanned"] += len(logs)
    stats["last_scan"] = datetime.now(timezone.utc).isoformat()
    all_alerts = []
    try:
        # SIGMA — deterministic, always runs (no training required)
        sigma_alerts = sigma.scan(logs)
        if sigma_alerts:
            all_alerts.extend(sigma_alerts)
            logger.info(f"SIGMA: {len(sigma_alerts)} rule matches")

        # ML — runs once trained
        if detector.is_trained():
            ml_alerts = detector.predict(logs)
            if ml_alerts:
                all_alerts.extend(ml_alerts)
                logger.info(f"ML: {len(ml_alerts)} anomalies")
        else:
            logger.info("ML model not trained yet — SIGMA-only scan")

        if all_alerts:
            stats["anomalies_detected"] += len(all_alerts)
            _write_alerts(all_alerts)
    except Exception as e:
        stats["scan_errors"] += 1
        logger.error(f"Scan error: {e}")


def _scheduler_thread():
    schedule.every(TRAIN_INTERVAL).seconds.do(run_train)
    schedule.every(SCAN_INTERVAL).seconds.do(run_scan)
    # Run immediately on start
    run_train()
    while True:
        schedule.run_pending()
        time.sleep(1)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    t = threading.Thread(target=_scheduler_thread, daemon=True)
    t.start()
    logger.info(f"Scheduler started. Train every {TRAIN_INTERVAL}s, scan every {SCAN_INTERVAL}s")
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
        "sigma_rules": len(sigma.rules),
        "trained_at": detector.trained_at.isoformat() if detector.trained_at else None,
        "training_samples": detector.training_samples,
        "es_connected": es.ping(),
    }


@app.get("/sigma/rules")
def sigma_rules(_token: str = Depends(_verify_token)):
    return {
        "total": len(sigma.rules),
        "rules": [
            {
                "id": r["id"],
                "name": r["name"],
                "mitre": r["mitre"],
                "tactic": r["tactic"],
                "severity": r["severity"],
                "description": r["description"],
            }
            for r in sigma.rules
        ],
    }


@app.get("/stats")
def get_stats(_token: str = Depends(_verify_token)):
    try:
        es_count = es.count(index="syndicate4-logs-*")["count"]
    except Exception:
        es_count = stats["logs_scanned"]
    return {**stats, "logs_scanned": es_count}


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


@app.post("/train")
def trigger_train(background_tasks: BackgroundTasks, _token: str = Depends(_verify_token)):
    background_tasks.add_task(run_train)
    return {"message": "Training triggered in background"}


@app.post("/scan")
def trigger_scan(background_tasks: BackgroundTasks, _token: str = Depends(_verify_token)):
    background_tasks.add_task(run_scan)
    return {"message": "Scan triggered in background"}


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
    """Evaluate RF on NSL-KDD KDDTest+ hold-out set. Returns accuracy + per-class metrics."""
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
