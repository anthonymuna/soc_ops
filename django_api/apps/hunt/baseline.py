"""
AgentBaselineWorker — daemon thread.
Runs every hour. Computes per-agent baselines and detects deviations.
"""
import threading
import time
import logging
import os
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch

logger = logging.getLogger("ngao.baseline")
ES_HOST = os.environ.get("ES_HOST", "http://elasticsearch:9200")


def compute_baseline(agent_name: str, es: Elasticsearch) -> dict:
    """
    Compute 30-day behavioural baseline for an agent.
    Returns dict matching AgentBaseline fields.
    """
    thirty_days_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

    r = es.search(index="syndicate4-ml-alerts", body={
        "query": {
            "bool": {
                "must": [
                    {"term": {"agent_name.keyword": agent_name}},
                    {"range": {"ml_detected_at": {"gte": thirty_days_ago}}}
                ]
            }
        },
        "size": 0,
        "aggs": {
            "by_hour": {
                "date_histogram": {
                    "field": "ml_detected_at",
                    "calendar_interval": "hour"
                }
            },
            "by_day_of_week": {
                "terms": {
                    "script": "doc['ml_detected_at'].value.dayOfWeekEnum.value",
                    "size": 7
                }
            },
            "top_src_ips": {"terms": {"field": "src_ip", "size": 10}},
            "top_dst_ports": {"terms": {"field": "dst_port", "size": 10}},
            "top_countries": {"terms": {"field": "src_country_iso.keyword", "size": 5}},
            "top_attack_classes": {"terms": {"field": "ml_rf_class.keyword", "size": 5}},
            "total": {"value_count": {"field": "ml_detected_at"}}
        }
    })

    aggs = r.get("aggregations", {})
    hourly_buckets = aggs.get("by_hour", {}).get("buckets", [])
    hourly_counts  = [b["doc_count"] for b in hourly_buckets] or [0]

    # Pure Python mean and standard deviation to avoid numpy dependency issues
    n = len(hourly_counts)
    avg_hourly = sum(hourly_counts) / n
    variance = sum((x - avg_hourly) ** 2 for x in hourly_counts) / n
    std_hourly = variance ** 0.5
    avg_daily  = avg_hourly * 24

    # Active hours: hours where count > 0 (local EAT = UTC+3)
    active_hours = []
    for b in hourly_buckets:
        hour_utc = datetime.fromisoformat(b["key_as_string"].replace("Z", "+00:00")).hour
        hour_eat = (hour_utc + 3) % 24
        if b["doc_count"] > 0 and hour_eat not in active_hours:
            active_hours.append(hour_eat)

    return {
        "avg_hourly_events":  float(avg_hourly),
        "avg_daily_events":   float(avg_daily),
        "std_hourly_events":  float(std_hourly),
        "active_hours":       sorted(active_hours),
        "active_days":        [b["key"] for b in aggs.get("by_day_of_week", {}).get("buckets", [])],
        "top_src_ips":        [b["key"] for b in aggs.get("top_src_ips", {}).get("buckets", [])],
        "top_dst_ports":      [b["key"] for b in aggs.get("top_dst_ports", {}).get("buckets", [])],
        "top_countries":      [b["key"] for b in aggs.get("top_countries", {}).get("buckets", [])],
        "top_attack_classes": [b["key"] for b in aggs.get("top_attack_classes", {}).get("buckets", [])],
        "data_days":          30,
    }


def detect_deviations(agent_name: str, baseline, es: Elasticsearch):
    """
    Compare last hour of activity against baseline.
    Create BaselineDeviation records for significant deviations.
    """
    from .models import BaselineDeviation
    from django.utils import timezone as dj_tz

    one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

    r = es.search(index="syndicate4-ml-alerts", body={
        "query": {
            "bool": {
                "must": [
                    {"term": {"agent_name.keyword": agent_name}},
                    {"range": {"ml_detected_at": {"gte": one_hour_ago}}}
                ]
            }
        },
        "size": 0,
        "aggs": {
            "total":          {"value_count": {"field": "ml_detected_at"}},
            "new_src_ips":    {"terms": {"field": "src_ip", "size": 20}},
            "new_ports":      {"terms": {"field": "dst_port", "size": 10}},
            "new_countries":  {"terms": {"field": "src_country_iso.keyword", "size": 5}},
            "attack_classes": {"terms": {"field": "ml_rf_class.keyword", "size": 5}},
        }
    })

    aggs = r.get("aggregations", {})
    current_hourly = r["hits"]["total"]["value"]

    deviations = []
    threshold = baseline.avg_hourly_events + (3 * baseline.std_hourly_events)

    # Volume spike: > 3 standard deviations above mean
    if current_hourly > threshold and baseline.avg_hourly_events > 0:
        factor = current_hourly / baseline.avg_hourly_events
        deviations.append({
            "deviation_type":   "volume_spike",
            "severity":         "critical" if factor > 10 else "high",
            "title":            f"Unusual log volume spike on {agent_name}",
            "description":      f"Agent is generating {current_hourly} events/hr, "
                                f"{factor:.1f}x above the 30-day baseline.",
            "observed_value":   f"{current_hourly} events/hr",
            "baseline_value":   f"{baseline.avg_hourly_events:.0f} events/hr",
            "deviation_factor": factor,
            "suggested_hyp":    "HYP-004",  # C2 Beaconing
        })

    # New countries not in baseline
    current_countries = [b["key"] for b in aggs.get("new_countries", {}).get("buckets", [])]
    new_countries = [c for c in current_countries if c and c not in baseline.top_countries]
    for country in new_countries:
        deviations.append({
            "deviation_type":   "new_country",
            "severity":         "high",
            "title":            f"New source country observed on {agent_name}: {country}",
            "description":      f"Traffic from {country} was not seen in the 30-day "
                                f"baseline for this agent.",
            "observed_value":   country,
            "baseline_value":   ", ".join(baseline.top_countries) or "None",
            "deviation_factor": 1.0,
            "suggested_hyp":    "HYP-007",  # Initial Access
        })

    # New destination ports not in baseline
    current_ports = [b["key"] for b in aggs.get("new_ports", {}).get("buckets", [])]
    new_ports = [p for p in current_ports if p and p not in baseline.top_dst_ports]
    for port in new_ports[:3]:  # max 3 port deviations at once
        deviations.append({
            "deviation_type":   "new_port",
            "severity":         "medium",
            "title":            f"New destination port on {agent_name}: {port}",
            "description":      f"Port {port} was not in the top-10 ports for "
                                f"this agent over the last 30 days.",
            "observed_value":   str(port),
            "baseline_value":   str(baseline.top_dst_ports[:5]),
            "deviation_factor": 1.0,
            "suggested_hyp":    "HYP-001",  # Port Scan
        })

    # New attack classes not in baseline
    current_classes = [b["key"] for b in aggs.get("attack_classes", {}).get("buckets", [])]
    new_classes = [c for c in current_classes
                   if c and c != "normal" and c not in baseline.top_attack_classes]
    for cls in new_classes:
        severity = "critical" if cls in ("u2r",) else "high" if cls in ("r2l",) else "medium"
        deviations.append({
            "deviation_type":   "attack_class_change",
            "severity":         severity,
            "title":            f"New attack class on {agent_name}: {cls.upper()}",
            "description":      f"Attack class '{cls}' was not in the baseline "
                                f"for this agent. Baseline classes: {baseline.top_attack_classes}",
            "observed_value":   cls.upper(),
            "baseline_value":   str(baseline.top_attack_classes),
            "deviation_factor": 1.0,
            "suggested_hyp":    "HYP-003" if cls == "r2l" else "HYP-006",
        })

    # Persist deviations
    for dev in deviations:
        # Avoid duplicate deviations within 2 hours
        recent = BaselineDeviation.objects.filter(
            agent_name=agent_name,
            deviation_type=dev["deviation_type"],
            detected_at__gte=dj_tz.now() - timedelta(hours=2)
        ).exists()
        if recent:
            continue

        suggested = None
        if dev.get("suggested_hyp"):
            try:
                from .models import HuntHypothesis
                suggested = HuntHypothesis.objects.get(
                    hypothesis_id=dev["suggested_hyp"])
            except Exception:
                pass

        BaselineDeviation.objects.create(
            agent_name=agent_name,
            baseline=baseline,
            deviation_type=dev["deviation_type"],
            severity=dev["severity"],
            title=dev["title"],
            description=dev["description"],
            observed_value=dev["observed_value"],
            baseline_value=dev["baseline_value"],
            deviation_factor=dev["deviation_factor"],
            suggested_hypothesis=suggested,
        )
        print(f"[AgentBaselineWorker] Deviation detected: {dev['title']}", flush=True)


def run_baseline_loop():
    """Daemon thread entry point."""
    print("[AgentBaselineWorker] Initializing loop... waiting 20s", flush=True)
    time.sleep(20)  # wait for Django to settle
    print("[AgentBaselineWorker] AgentBaselineWorker started", flush=True)
    es = Elasticsearch(ES_HOST)

    while True:
        try:
            _update_all_baselines(es)
            _detect_all_deviations(es)
        except Exception as e:
            print(f"[AgentBaselineWorker] Baseline loop error: {e}", flush=True)
        time.sleep(3600)  # run every hour


def _update_all_baselines(es):
    """Discover all agents from ES and update their baselines."""
    from .models import AgentBaseline
    r = es.search(index="syndicate4-ml-alerts", body={
        "size": 0,
        "aggs": {"agents": {"terms": {"field": "agent_name.keyword", "size": 100}}}
    })
    for bucket in r["aggregations"]["agents"]["buckets"]:
        agent = bucket["key"]
        if not agent or agent == "unknown":
            continue
        try:
            data = compute_baseline(agent, es)
            AgentBaseline.objects.update_or_create(
                agent_name=agent, defaults=data)
        except Exception as e:
            print(f"[AgentBaselineWorker] Baseline compute failed for {agent}: {e}", flush=True)


def _detect_all_deviations(es):
    """Run deviation detection for every agent with a baseline."""
    from .models import AgentBaseline
    for baseline in AgentBaseline.objects.all():
        try:
            detect_deviations(baseline.agent_name, baseline, es)
        except Exception as e:
            print(f"[AgentBaselineWorker] Deviation detect failed for {baseline.agent_name}: {e}", flush=True)


def start_worker():
    t = threading.Thread(
        target=run_baseline_loop, daemon=True, name="AgentBaselineWorker")
    t.start()
    print("[AgentBaselineWorker] AgentBaselineWorker thread launched", flush=True)
