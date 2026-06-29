import httpx
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.http import StreamingHttpResponse, JsonResponse
from elasticsearch import Elasticsearch, NotFoundError
import os
from .models import AlertFeedback

es = Elasticsearch(settings.ES_HOST)

QWEN_API_URL = os.getenv("QWEN_API_URL", "https://localhost/v1").rstrip('/')
QWEN_API_KEY = os.getenv("QWEN_API_KEY", "")

class AlertsListView(APIView):
    def get(self, request):
        limit = int(request.GET.get('limit', 50))
        minutes = int(request.GET.get('minutes', 60))
        connector = request.GET.get('connector')
        timeframe = request.GET.get('timeframe', 'live')
        
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        
        must_clauses = []
        if timeframe == 'yesterday':
            start_of_yesterday = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            end_of_yesterday = start_of_yesterday.replace(hour=23, minute=59, second=59)
            must_clauses.append({"range": {"ml_detected_at": {"gte": start_of_yesterday.isoformat(), "lte": end_of_yesterday.isoformat()}}})
        elif timeframe == 'today':
            start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
            must_clauses.append({"range": {"ml_detected_at": {"gte": start_of_today.isoformat()}}})
        else:
            since = (now - timedelta(minutes=minutes)).isoformat()
            must_clauses.append({"range": {"ml_detected_at": {"gte": since}}})
        if connector:
            must_clauses.append({"term": {"connector.keyword": connector}})

        try:
            resp = es.search(
                index="syndicate4-ml-alerts",
                body={
                    "query": {"bool": {"must": must_clauses}},
                    "size": limit,
                    "sort": [{"ml_detected_at": {"order": "desc"}}],
                },
            )
            return Response({
                "total": resp["hits"]["total"]["value"],
                "alerts": [h["_source"] for h in resp["hits"]["hits"]]
            })
        except NotFoundError:
            return Response({"total": 0, "alerts": []})

class AlertDetailView(APIView):
    def get(self, request, pk):
        try:
            resp = es.search(index="syndicate4-ml-alerts", body={"query": {"match": {"_id": pk}}})
            if not resp["hits"]["hits"]:
                resp = es.search(index="syndicate4-ml-alerts", body={"query": {"term": {"id": pk}}})
                if not resp["hits"]["hits"]:
                    return Response({"detail": "Not found."}, status=404)
            return Response(resp["hits"]["hits"][0]["_source"])
        except Exception as e:
            return Response({"error": str(e)}, status=500)

class AlertFeedbackView(APIView):
    def post(self, request, pk):
        label = request.data.get('label')
        comment = request.data.get('comment', '')
        
        # Incorporate the user info into the comment
        user_comment = comment
        if request.user and request.user.username:
             user_comment = f"[{request.user.username}] {comment}"
        
        # Save to PostgreSQL
        feedback = AlertFeedback.objects.create(
            alert_id=pk,
            label=label,
            comment=comment,
            submitted_by=request.user
        )
        
        # Call ml_service
        try:
            with httpx.Client() as client:
                res = client.post(
                    f"{settings.ML_SERVICE_URL}/alerts/{pk}/feedback",
                    json={"label": label, "comment": user_comment},
                    timeout=10
                )
                res.raise_for_status()
        except Exception as e:
            return Response({"error": f"Failed to reach ML service: {str(e)}"}, status=500)
            
        return Response({"status": "success", "id": feedback.id})

class AlertReportView(APIView):
    def get(self, request, pk):
        with httpx.Client() as client:
            req = client.build_request("GET", f"{settings.ML_SERVICE_URL}/alerts/{pk}/report")
            r = client.send(req, stream=True)
            return StreamingHttpResponse(
                r.iter_bytes(),
                content_type=r.headers.get("content-type", "application/pdf"),
                headers={"Content-Disposition": r.headers.get("content-disposition", "")}
            )

import socket

def check_tcp(host, port, timeout=1):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def check_host(host):
    try:
        socket.gethostbyname(host)
        return True
    except Exception:
        return False

class MLProxyView(APIView):
    def handle_request(self, request, path):
        url = f"{settings.ML_SERVICE_URL}/{path}"
        try:
            with httpx.Client() as client:
                query_string = request.META.get('QUERY_STRING', '')
                if query_string:
                    url = f"{url}?{query_string}"
                
                # Check for body safely
                json_data = None
                if request.method in ['POST', 'PUT', 'PATCH'] and request.body:
                    try:
                        json_data = request.data
                    except:
                        pass

                req = client.build_request(request.method, url, json=json_data)
                r = client.send(req)
                
                if path == 'health':
                    data = r.json() if r.status_code == 200 else {}
                    data['es_connected'] = check_tcp('elasticsearch', 9200)
                    data['kafka_connected'] = check_tcp('kafka', 9092)
                    data['brain_connected'] = check_tcp('ngao_brain', 9000)
                    data['wazuh_connected'] = check_host('wazuh_connector')
                    data['fortisiem_connected'] = check_host('fortisiem_connector')
                    data['umbrella_connected'] = check_host('umbrella_connector')
                    data['django_connected'] = True
                    data['status'] = 'ok' if r.status_code == 200 else 'error'
                    return Response(data, status=200)

                return Response(r.json(), status=r.status_code)
        except Exception as e:
            if path == 'health':
                return Response({
                    "status": "error",
                    "es_connected": check_tcp('elasticsearch', 9200),
                    "kafka_connected": check_tcp('kafka', 9092),
                    "brain_connected": check_tcp('ngao_brain', 9000),
                    "wazuh_connected": check_host('wazuh_connector'),
                    "fortisiem_connected": check_host('fortisiem_connector'),
                    "umbrella_connected": check_host('umbrella_connector'),
                    "django_connected": True
                }, status=200)
            return Response({"error": str(e)}, status=500)

    def get(self, request, *args, **kwargs):
        return self.handle_request(request, kwargs.get('path', ''))

    def post(self, request, *args, **kwargs):
        return self.handle_request(request, kwargs.get('path', ''))

class PredictiveAnalysisView(APIView):
    def get(self, request):
        limit = int(request.GET.get('limit', 25))
        from datetime import datetime, timezone, timedelta
        since = (datetime.now(timezone.utc) - timedelta(days=70)).isoformat()
        
        must_clauses = [
            {"range": {"ml_detected_at": {"gte": since}}},
            {"term": {"connector.keyword": "wazuh"}}
        ]
        try:
            resp = es.search(
                index="syndicate4-ml-alerts",
                body={
                    "query": {"bool": {"must": must_clauses}},
                    "size": limit,
                    "sort": [{"ml_detected_at": {"order": "desc"}}],
                },
            )
            alerts = [h["_source"] for h in resp["hits"]["hits"]]
        except NotFoundError:
            alerts = []

        if not alerts:
            return Response({"analysis": "No recent Wazuh anomalies found to perform predictive analysis."})

        prompt_lines = ["Analyze the following recent security anomalies and predict potential attacker intent or next steps. Highlight critical risks:\n"]
        for a in alerts:
            ts = a.get('ml_detected_at', '')
            evt = a.get('event_type', '')
            desc = a.get('wazuh_description', '')
            if len(desc) > 100:
                desc = desc[:97] + '...'
            src = a.get('src_ip', 'Unknown')
            dst = a.get('dst_ip', 'Unknown')
            mitre = a.get('mitre_techniques', [])
            prompt_lines.append(f"- Time: {ts} | Type: {evt} | Desc: {desc} | Src: {src} | Dst: {dst} | MITRE: {mitre}")
        
        prompt = "\n".join(prompt_lines)
        
        system_prompt = (
            "You are a senior SOC analyst. Provide a predictive threat analysis of the provided anomalies. "
            "IMPORTANT: Interconnect your analysis with the MITRE ATT&CK framework. "
            "The system actively monitors these specific MITRE techniques: "
            "T1046 (Net Scan), T1018 (Remote Sys), T1049 (Net Conns), T1057 (Proc Disc), T1082 (Sys Info), T1083 (File Disc), "
            "T1078 (Valid Accts), T1110 (Brute Force), T1110.001 (Pwd Guess), T1021 (Remote Svc), T1041 (Exfil C2), "
            "T1071 (C2 Beacon), T1105 (Tool Transfer), T1059 (Cmd Exec), T1068 (Priv Esc), T1498 (Net DoS). "
            "You must explicitly predict the NEXT likely MITRE techniques the attacker will attempt from this list, "
            "and explain how the current anomalies map to the MITRE framework."
        )

        payload = {
            "model": os.getenv("QWEN_MODEL", "qwen-military-advisor-q8_0_v2.gguf"),
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 800
        }
        
        try:
            with httpx.Client(verify=False) as client:
                res = client.post(
                    f"{QWEN_API_URL}/chat/completions",
                    headers={"Authorization": f"Bearer {QWEN_API_KEY}"},
                    json=payload,
                    timeout=45
                )
                res.raise_for_status()
                data = res.json()
                analysis = data['choices'][0]['message']['content']
        except httpx.HTTPStatusError as e:
            err_text = e.response.text
            return Response({"analysis": f"**API Validation Error**: Qwen rejected the payload.\n\n**Details:**\n`{err_text}`"})
        except Exception as e:
            return Response({"analysis": f"**System Error**: Failed to reach Qwen AI endpoint (`10.101.7.72`).\n\n**Details:**\n`{str(e)}`"})
        return Response({"analysis": analysis})


class ThreatIntelligenceView(APIView):
    """
    Reads pre-enriched ThreatActorProfile records from PostgreSQL.
    ZERO live API calls — all enrichment happens in the background worker.
    Fast, consistent, cacheable.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from .models import ThreatActorProfile
        from django.db.models import Count

        threat_level = request.query_params.get("threat_level")
        country_iso  = request.query_params.get("country")
        min_score    = int(request.query_params.get("min_score", 0))
        limit        = int(request.query_params.get("limit", 50))

        qs = ThreatActorProfile.objects.filter(
            enrichment_status="complete",
            is_whitelisted=False
        )

        if threat_level:
            qs = qs.filter(threat_level=threat_level)
        if country_iso:
            qs = qs.filter(country_iso=country_iso)
        if min_score > 0:
            qs = qs.filter(abuse_score__gte=min_score)

        qs = qs.order_by("-last_seen")[:limit]

        profiles = []
        for p in qs:
            profiles.append({
                # Identity
                "ip":                   p.ip_address,
                "threat_level":         p.threat_level,
                "composite_score":      p.composite_threat_score,
                "attacker_type":        p.attacker_type,
                "campaign_name":        p.campaign_name,

                # Geography
                "location":             f"{p.city}, {p.country}" if p.city else p.country,
                "country_iso":          p.country_iso,
                "continent":            p.continent,
                "latitude":             p.latitude,
                "longitude":            p.longitude,

                # Network
                "asn":                  p.asn,
                "asn_org":              p.asn_org,
                "isp":                  p.isp,
                "connection_type":      p.connection_type,
                "is_tor":               p.is_tor_exit_node,
                "is_proxy":             p.is_anonymous_proxy,
                "is_hosting":           p.is_hosting_provider,

                # External intel
                "abuse_score":          p.abuse_score,
                "abuse_reports":        p.abuse_total_reports,
                "abuse_last_reported":  p.abuse_last_reported,
                "vt_malicious":         p.vt_malicious_count,
                "vt_suspicious":        p.vt_suspicious_count,

                # Internal history
                "first_seen":           p.first_seen,
                "last_seen":            p.last_seen,
                "total_events":         p.total_events,
                "attack_classes":       p.attack_classes,
                "mitre_techniques":     p.mitre_techniques,
                "targeted_agents":      p.targeted_agents,
                "connectors_seen":      p.connectors_seen,

                # Qwen analysis
                "threat_summary":       p.threat_summary,
                "recommended_actions":  p.recommended_actions,
                "analyst_notes":        p.analyst_notes,

                # Meta
                "is_blocked":           p.is_blocked,
                "enriched_at":          p.updated_at,
            })

        # Summary stats for dashboard header
        all_profiles = ThreatActorProfile.objects.filter(
            enrichment_status="complete",
            is_whitelisted=False
        )
        summary = {
            "total_ips":      all_profiles.count(),
            "critical_count": all_profiles.filter(threat_level="critical").count(),
            "high_count":     all_profiles.filter(threat_level="high").count(),
            "pending_count":  ThreatActorProfile.objects.filter(
                                  enrichment_status__in=["pending","enriching"]).count(),
            "top_countries":  list(
                all_profiles.values("country_iso")
                .annotate(count=Count("id"))
                .order_by("-count")[:5]
            ),
        }

        return Response({"intelligence": profiles, "summary": summary})

class ThreatActorDetailView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, ip):
        from .models import ThreatActorProfile
        try:
            p = ThreatActorProfile.objects.get(ip_address=ip)
            return Response({
                "ip":                   p.ip_address,
                "threat_level":         p.threat_level,
                "composite_score":      p.composite_threat_score,
                "attacker_type":        p.attacker_type,
                "campaign_name":        p.campaign_name,
                "location":             f"{p.city}, {p.country}" if p.city else p.country,
                "city":                 p.city,
                "country":              p.country,
                "country_iso":          p.country_iso,
                "continent":            p.continent,
                "latitude":             p.latitude,
                "longitude":            p.longitude,
                "asn":                  p.asn,
                "asn_org":              p.asn_org,
                "isp":                  p.isp,
                "connection_type":      p.connection_type,
                "is_tor":               p.is_tor_exit_node,
                "is_proxy":             p.is_anonymous_proxy,
                "is_hosting":           p.is_hosting_provider,
                "abuse_score":          p.abuse_score,
                "abuse_reports":        p.abuse_total_reports,
                "abuse_last_reported":  p.abuse_last_reported,
                "vt_malicious":         p.vt_malicious_count,
                "vt_suspicious":        p.vt_suspicious_count,
                "first_seen":           p.first_seen,
                "last_seen":            p.last_seen,
                "total_events":         p.total_events,
                "attack_classes":       p.attack_classes,
                "mitre_techniques":     p.mitre_techniques,
                "targeted_agents":      p.targeted_agents,
                "connectors_seen":      p.connectors_seen,
                "threat_summary":       p.threat_summary,
                "recommended_actions":  p.recommended_actions,
                "analyst_notes":        p.analyst_notes,
                "is_blocked":           p.is_blocked,
                "enriched_at":          p.updated_at,
            })
        except ThreatActorProfile.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)

class WhitelistIPView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, ip):
        from .models import ThreatActorProfile
        try:
            p = ThreatActorProfile.objects.get(ip_address=ip)
            p.is_whitelisted = True
            p.save()
            return Response({"status": "success", "message": f"IP {ip} whitelisted."})
        except ThreatActorProfile.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)

class TriggerEnrichmentView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        ip = request.data.get("ip")
        if not ip:
            return Response({"error": "Missing IP parameter"}, status=400)
        from .models import ThreatActorProfile
        p, created = ThreatActorProfile.objects.get_or_create(ip_address=ip)
        p.enrichment_status = "pending"
        p.save()
        
        # Trigger enrichment in a separate thread so the HTTP call remains non-blocking
        import threading
        from .enrichment import enrich_maxmind, enrich_abuseipdb, enrich_virustotal, get_internal_history, analyze_with_qwen, MAXMIND_ID, MAXMIND_KEY
        import geoip2.webservice
        from django.utils import timezone as dj_tz
        
        def run_single_enrichment():
            try:
                p.enrichment_status = "enriching"
                p.save()
                mm_client = None
                if MAXMIND_ID and MAXMIND_KEY:
                    mm_client = geoip2.webservice.Client(MAXMIND_ID, MAXMIND_KEY, host="geolite.info")
                if mm_client:
                    mm_data = enrich_maxmind(p.ip_address, mm_client)
                    for f, v in mm_data.items():
                        setattr(p, f, v)
                    p.maxmind_enriched_at = dj_tz.now()
                ab_data = enrich_abuseipdb(p.ip_address)
                for f, v in ab_data.items():
                    if v is not None:
                        setattr(p, f, v)
                vt_data = enrich_virustotal(p.ip_address)
                for f, v in vt_data.items():
                    setattr(p, f, v)
                hist = get_internal_history(p.ip_address)
                for f, v in hist.items():
                    if v is not None:
                        setattr(p, f, v)
                qwen_res = analyze_with_qwen(p)
                if qwen_res:
                    p.threat_level = qwen_res.get("threat_level", "unknown")
                    p.attacker_type = qwen_res.get("attacker_type", "unknown")
                    p.campaign_name = qwen_res.get("campaign_name", "")
                    p.threat_summary = qwen_res.get("threat_summary", "")
                    p.recommended_actions = qwen_res.get("recommended_actions", [])
                    p.analyst_notes = qwen_res.get("analyst_notes", "")
                    p.qwen_analyzed_at = dj_tz.now()
                p.enrichment_status = "complete"
                p.save()
            except Exception as e:
                p.enrichment_status = "failed"
                p.save()
                
        threading.Thread(target=run_single_enrichment, daemon=True).start()
        return Response({"status": "success", "message": f"Enrichment triggered for {ip}."})

class ThreatIntelStatsView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        from .models import ThreatActorProfile
        all_profiles = ThreatActorProfile.objects.filter(is_whitelisted=False)
        return Response({
            "total_ips": all_profiles.count(),
            "critical_count": all_profiles.filter(threat_level="critical").count(),
            "high_count": all_profiles.filter(threat_level="high").count(),
            "pending_count": ThreatActorProfile.objects.filter(enrichment_status__in=["pending", "enriching"]).count()
        })
