"""
ThreatEnrichmentWorker — runs as a background thread inside Django.
Polls for unenriched IPs every 60 seconds.
Does NOT use Celery — runs in a daemon thread started by Django AppConfig.ready()
"""
import threading, time, os, logging
from datetime import datetime, timezone, timedelta
import geoip2.webservice
import geoip2.errors
import httpx
from django.utils import timezone as dj_tz

logger = logging.getLogger("ngao.enrichment")

ABUSEIPDB_KEY  = os.environ.get("ABUSEIPDB_API_KEY", "")
VT_KEY         = os.environ.get("VIRUSTOTAL_API_KEY", "")
MAXMIND_ID     = int(os.environ.get("MAXMIND_ACCOUNT_ID", "0"))
MAXMIND_KEY    = os.environ.get("MAXMIND_LICENSE_KEY", "")
ENRICHMENT_TTL = int(os.environ.get("ENRICHMENT_TTL_HOURS", "24"))  # re-enrich after 24h


def enrich_maxmind(ip: str, client: geoip2.webservice.Client) -> dict:
    """
    Extract ALL available MaxMind fields — not just city/country.
    """
    result = {}
    try:
        r = client.city(ip)
        result.update({
            "city":                r.city.name or "",
            "country":             r.country.name or "",
            "country_iso":         r.country.iso_code or "",
            "continent":           r.continent.name or "",
            "latitude":            r.location.latitude,
            "longitude":           r.location.longitude,
            "is_anonymous_proxy":  r.traits.is_anonymous_proxy or False,
            "is_hosting_provider": r.traits.is_hosting_provider or False,
        })
    except geoip2.errors.GeoIP2Error as e:
        logger.warning(f"MaxMind city failed for {ip}: {e}")

    try:
        r = client.asn(ip)
        result.update({
            "asn":     f"AS{r.autonomous_system_number}",
            "asn_org": r.autonomous_system_organization or "",
        })
    except Exception:
        pass

    try:
        r = client.connection_type(ip)
        result["connection_type"] = r.connection_type or ""
    except Exception:
        pass

    try:
        r = client.isp(ip)
        result["isp"] = r.isp or ""
    except Exception:
        pass

    return result


def enrich_abuseipdb(ip: str) -> dict:
    """
    Query AbuseIPDB for abuse history.
    Returns zeroed dict if key not configured.
    """
    if not ABUSEIPDB_KEY:
        return {"abuse_score": 0, "abuse_total_reports": 0,
                "abuse_categories": [], "abuse_last_reported": None}
    try:
        r = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10
        )
        if r.status_code == 200:
            d = r.json()["data"]
            return {
                "abuse_score":         d.get("abuseConfidenceScore", 0),
                "abuse_total_reports": d.get("totalReports", 0),
                "abuse_categories":    d.get("categories", []),
                "abuse_last_reported": d.get("lastReportedAt"),
                "abuseipdb_enriched_at": dj_tz.now().isoformat(),
            }
    except Exception as e:
        logger.warning(f"AbuseIPDB failed for {ip}: {e}")
    return {"abuse_score": 0, "abuse_total_reports": 0,
            "abuse_categories": [], "abuse_last_reported": None}


def enrich_virustotal(ip: str) -> dict:
    """
    Query VirusTotal for vendor detections.
    Optional — skipped if VT_KEY not set.
    """
    if not VT_KEY:
        return {"vt_malicious_count": 0, "vt_suspicious_count": 0,
                "vt_harmless_count": 0}
    try:
        r = httpx.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_KEY},
            timeout=10
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "vt_malicious_count":  stats.get("malicious", 0),
                "vt_suspicious_count": stats.get("suspicious", 0),
                "vt_harmless_count":   stats.get("harmless", 0),
                "vt_enriched_at":      dj_tz.now().isoformat(),
            }
    except Exception as e:
        logger.warning(f"VirusTotal failed for {ip}: {e}")
    return {"vt_malicious_count": 0, "vt_suspicious_count": 0,
            "vt_harmless_count": 0}


def get_internal_history(ip: str) -> dict:
    """
    Aggregate NGAO SOC's own observed data for this IP from ES.
    """
    from elasticsearch import Elasticsearch
    es = Elasticsearch(os.environ.get("ES_HOST", "http://elasticsearch:9200"))
    try:
        r = es.search(index="syndicate4-ml-alerts", body={
            "query": {"term": {"src_ip": ip}},
            "size": 0,
            "aggs": {
                "first_seen":   {"min": {"field": "ml_detected_at"}},
                "last_seen":    {"max": {"field": "ml_detected_at"}},
                "attack_classes": {"terms": {"field": "ml_rf_class.keyword", "size": 10}},
                "mitre":        {"terms": {"field": "mitre_techniques.keyword", "size": 20}},
                "agents":       {"terms": {"field": "agent_name.keyword", "size": 20}},
                "connectors":   {"terms": {"field": "connector.keyword", "size": 10}},
            }
        })
        aggs = r.get("aggregations", {})
        return {
            "total_events":    r["hits"]["total"]["value"],
            "first_seen":      aggs.get("first_seen", {}).get("value_as_string"),
            "last_seen":       aggs.get("last_seen", {}).get("value_as_string"),
            "attack_classes":  [b["key"] for b in aggs.get("attack_classes", {}).get("buckets", [])],
            "mitre_techniques":[b["key"] for b in aggs.get("mitre", {}).get("buckets", [])],
            "targeted_agents": [b["key"] for b in aggs.get("agents", {}).get("buckets", [])],
            "connectors_seen": [b["key"] for b in aggs.get("connectors", {}).get("buckets", [])],
        }
    except Exception as e:
        logger.warning(f"ES history failed for {ip}: {e}")
        return {"total_events": 0}


def analyze_with_qwen(profile) -> dict:
    """
    Send enriched profile to Qwen for threat assessment.
    Structured output with specific SOC-grade fields.
    """
    system_prompt = """You are a cybersecurity threat intelligence analyst for 
NGAO SOC, a Security Operations Center monitoring networks across East Africa 
(Kenya, Uganda, Tanzania, Rwanda).

Analyze the provided IP enrichment data and return a JSON object with these 
exact fields:
{
  "threat_level": "critical|high|medium|low",
  "attacker_type": "apt|targeted|opportunistic|scanner|botnet|unknown",
  "campaign_name": "short descriptive name for this threat activity or empty string",
  "threat_summary": "2-3 sentence plain English summary of the threat",
  "recommended_actions": [
    "Specific action 1",
    "Specific action 2", 
    "Specific action 3"
  ],
  "analyst_notes": "detailed technical notes including context about the ASN, 
    geographic origin significance, attack pattern analysis, and any known 
    threat actor associations"
}

Context: East African SOC environment. Hosting providers in certain regions 
are commonly used as VPN exit nodes by APT groups. Tor exit nodes and 
anonymous proxies should be treated as high risk by default.
Return JSON ONLY. No markdown. No preamble."""

    user_content = f"""IP: {profile.ip_address}
Location: {profile.city}, {profile.country} ({profile.country_iso})
ASN: {profile.asn} — {profile.asn_org}
ISP: {profile.isp}
Connection Type: {profile.connection_type}
Is Hosting Provider: {profile.is_hosting_provider}
Is Anonymous Proxy: {profile.is_anonymous_proxy}
Is Tor Exit Node: {profile.is_tor_exit_node}
AbuseIPDB Score: {profile.abuse_score}/100
AbuseIPDB Reports: {profile.abuse_total_reports}
VirusTotal Malicious Vendors: {profile.vt_malicious_count}
First Seen: {profile.first_seen}
Last Seen: {profile.last_seen}
Total Events in NGAO SOC: {profile.total_events}
Attack Classes Observed: {profile.attack_classes}
MITRE Techniques: {profile.mitre_techniques}
Targeted Agents: {profile.targeted_agents}
Seen via Connectors: {profile.connectors_seen}
Composite Threat Score: {profile.composite_threat_score}/100"""

    qwen_api_url = os.environ.get("QWEN_API_URL", "https://10.101.7.72/v1").rstrip('/') + "/chat/completions"
    qwen_api_key = os.environ.get("QWEN_API_KEY", "57be7935b6f361750802cd937f3252d21ce14eab9b8acfcf9a40e53e7cf13486")
    qwen_model = os.environ.get("QWEN_MODEL", "qwen-military-advisor-q8_0_v2.gguf")

    try:
        with httpx.Client(verify=False, timeout=45) as client:
            r = client.post(
                qwen_api_url,
                headers={"Authorization": f"Bearer {qwen_api_key}"},
                json={
                    "model": qwen_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_content}
                    ],
                    "max_tokens": 600,
                    "temperature": 0.1
                }
            )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"].strip()
            content = content.replace("```json", "").replace("```", "").strip()
            import json
            return json.loads(content)
    except Exception as e:
        logger.error(f"Qwen analysis failed for {profile.ip_address}: {e}")
        return {}


def run_enrichment_loop():
    """
    Background thread — discovers new IPs from ES, enriches them,
    and periodically re-enriches stale profiles.
    """
    print("[ThreatEnrichmentWorker] Initializing loop... waiting 15s", flush=True)
    # Wait for Django to fully start
    time.sleep(15)
    print("[ThreatEnrichmentWorker] ThreatEnrichmentWorker started", flush=True)

    # Initialize MaxMind client once — reuse across all enrichments
    mm_client = None
    if MAXMIND_ID and MAXMIND_KEY:
        mm_client = geoip2.webservice.Client(MAXMIND_ID, MAXMIND_KEY, host="geolite.info")

    while True:
        try:
            _discover_new_ips()
            _enrich_pending(mm_client)
            _reanalyze_stale_qwen()
        except Exception as e:
            print(f"[ThreatEnrichmentWorker] Enrichment loop error: {e}", flush=True)
        time.sleep(60)


def _discover_new_ips():
    """Find IPs in ES that don't have a ThreatActorProfile yet."""
    from elasticsearch import Elasticsearch
    from .models import ThreatActorProfile
    
    es = Elasticsearch(os.environ.get("ES_HOST", "http://elasticsearch:9200"))
    try:
        r = es.search(index="syndicate4-ml-alerts", body={
            "query": {"range": {"ml_detected_at": {"gte": "now-90d"}}},
            "size": 0,
            "aggs": {"unique_ips": {"terms": {"field": "src_ip", "size": 200}}}
        })
        known_ips = set(ThreatActorProfile.objects.values_list("ip_address", flat=True))
        
        discovered = 0
        for bucket in r["aggregations"]["unique_ips"]["buckets"]:
            ip = bucket["key"]
            if ip in ("unknown", "0.0.0.0", "") or ip in known_ips:
                continue
            ThreatActorProfile.objects.get_or_create(
                ip_address=ip,
                defaults={"enrichment_status": "pending"}
            )
            discovered += 1
        if discovered > 0:
            print(f"[ThreatEnrichmentWorker] Discovered {discovered} new IPs from ES logs.", flush=True)
    except Exception as e:
        print(f"[ThreatEnrichmentWorker] IP discovery failed: {e}", flush=True)


def _enrich_pending(mm_client):
    """Enrich all pending ThreatActorProfiles."""
    from .models import ThreatActorProfile
    
    pending = ThreatActorProfile.objects.filter(
        enrichment_status__in=["pending", "failed"]
    )[:20]  # max 20 per cycle to respect rate limits

    if pending.exists():
        print(f"[ThreatEnrichmentWorker] Found {pending.count()} pending IPs to enrich.", flush=True)

    for profile in pending:
        try:
            print(f"[ThreatEnrichmentWorker] Enriching IP: {profile.ip_address}...", flush=True)
            profile.enrichment_status = "enriching"
            profile.save(update_fields=["enrichment_status"])

            # MaxMind
            if mm_client:
                mm_data = enrich_maxmind(profile.ip_address, mm_client)
                for field, value in mm_data.items():
                    setattr(profile, field, value)
                profile.maxmind_enriched_at = dj_tz.now()

            # AbuseIPDB
            ab_data = enrich_abuseipdb(profile.ip_address)
            for field, value in ab_data.items():
                if value is not None:
                    setattr(profile, field, value)

            # VirusTotal
            vt_data = enrich_virustotal(profile.ip_address)
            for field, value in vt_data.items():
                setattr(profile, field, value)

            # Internal ES history
            hist = get_internal_history(profile.ip_address)
            for field, value in hist.items():
                if value is not None:
                    setattr(profile, field, value)

            # Qwen analysis
            print(f"[ThreatEnrichmentWorker] Requesting Qwen assessment for {profile.ip_address}...", flush=True)
            qwen_result = analyze_with_qwen(profile)
            if qwen_result:
                profile.threat_level        = qwen_result.get("threat_level", "unknown")
                profile.attacker_type       = qwen_result.get("attacker_type", "unknown")
                profile.campaign_name       = qwen_result.get("campaign_name", "")
                profile.threat_summary      = qwen_result.get("threat_summary", "")
                profile.recommended_actions = qwen_result.get("recommended_actions", [])
                profile.analyst_notes       = qwen_result.get("analyst_notes", "")
                profile.qwen_analyzed_at    = dj_tz.now()

            profile.enrichment_status = "complete"
            profile.save()
            print(f"[ThreatEnrichmentWorker] Enriched {profile.ip_address} → {profile.threat_level}", flush=True)

        except Exception as e:
            profile.enrichment_status = "failed"
            profile.save(update_fields=["enrichment_status"])
            print(f"[ThreatEnrichmentWorker] Enrichment failed for {profile.ip_address}: {e}", flush=True)


def _reanalyze_stale_qwen():
    """Re-run Qwen analysis on profiles not analyzed in 24h."""
    from .models import ThreatActorProfile
    cutoff = dj_tz.now() - timedelta(hours=ENRICHMENT_TTL)
    stale = ThreatActorProfile.objects.filter(
        enrichment_status="complete",
        qwen_analyzed_at__lt=cutoff
    )[:5]  # max 5 per cycle — Qwen is slow

    for profile in stale:
        try:
            print(f"[ThreatEnrichmentWorker] Re-analyzing stale profile: {profile.ip_address}...", flush=True)
            # Refresh internal history first
            hist = get_internal_history(profile.ip_address)
            for field, value in hist.items():
                if value is not None:
                    setattr(profile, field, value)

            qwen_result = analyze_with_qwen(profile)
            if qwen_result:
                profile.threat_level        = qwen_result.get("threat_level", profile.threat_level)
                profile.attacker_type       = qwen_result.get("attacker_type", profile.attacker_type)
                profile.campaign_name       = qwen_result.get("campaign_name", profile.campaign_name)
                profile.threat_summary      = qwen_result.get("threat_summary", profile.threat_summary)
                profile.recommended_actions = qwen_result.get("recommended_actions", profile.recommended_actions)
                profile.analyst_notes       = qwen_result.get("analyst_notes", profile.analyst_notes)
                profile.qwen_analyzed_at    = dj_tz.now()
            profile.save()
        except Exception as e:
            print(f"[ThreatEnrichmentWorker] Stale re-analysis failed for {profile.ip_address}: {e}", flush=True)


def start_worker():
    """Start enrichment worker as daemon thread."""
    t = threading.Thread(target=run_enrichment_loop, daemon=True, name="ThreatEnrichmentWorker")
    t.start()
    print("[ThreatEnrichmentWorker] ThreatEnrichmentWorker thread launched", flush=True)
