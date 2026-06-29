import os
import httpx
from django.conf import settings
from datetime import datetime, timezone, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError
from django.http import HttpResponse
from elasticsearch import Elasticsearch, NotFoundError

from .models import ReportJob, DailyReport
from .serializers import DailyReportSerializer
from apps.alerts.models import ThreatActorProfile
from apps.hunt.models import HuntCampaign, BaselineDeviation

ES_HOST = os.environ.get("ES_HOST", "http://elasticsearch:9200")
es = Elasticsearch(ES_HOST)

QWEN_API_URL = os.environ.get("QWEN_API_URL", "https://10.101.7.72/v1").rstrip('/')
QWEN_API_KEY = os.environ.get("QWEN_API_KEY", "57be7935b6f361750802cd937f3252d21ce14eab9b8acfcf9a40e53e7cf13486")
QWEN_MODEL   = os.environ.get("QWEN_MODEL", "qwen-military-advisor-q8_0_v2.gguf")


class ReportDownloadView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        hours = request.GET.get('hours', 24)
        ReportJob.objects.create(
            requested_by=request.user,
            hours=hours,
            status='completed'
        )
        with httpx.Client(timeout=60.0) as client:
            r = client.get(f"{settings.ML_SERVICE_URL}/report", params={"hours": hours})
            return HttpResponse(
                r.content,
                content_type=r.headers.get("content-type", "application/pdf"),
                headers={"Content-Disposition": r.headers.get("content-disposition", "")}
            )


class DailyReportListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        reports = DailyReport.objects.all()
        serializer = DailyReportSerializer(reports, many=True)
        return Response(serializer.data)

    def post(self, request):
        hours = int(request.data.get("hours", 24))
        
        # 1. Fetch Alert Stats from Elasticsearch
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        try:
            r = es.search(index="syndicate4-ml-alerts", body={
                "query": {
                    "range": {"ml_detected_at": {"gte": since}}
                },
                "size": 0,
                "aggs": {
                    "by_severity": {"terms": {"field": "ml_severity.keyword"}},
                    "by_class": {"terms": {"field": "ml_rf_class.keyword"}},
                    "by_event": {"terms": {"field": "event_type.keyword"}},
                    "by_time": {
                        "date_histogram": {
                            "field": "ml_detected_at",
                            "calendar_interval": "1h" if hours <= 48 else "1d",
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": since,
                                "max": datetime.now(timezone.utc).isoformat()
                            }
                        }
                    }
                }
            })
            total_alerts = r["hits"]["total"]["value"] if isinstance(r["hits"]["total"], dict) else r["hits"]["total"]
            aggs = r.get("aggregations", {})
            severities = {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])}
            classes = {b["key"]: b["doc_count"] for b in aggs.get("by_class", {}).get("buckets", [])}
            events = {b["key"]: b["doc_count"] for b in aggs.get("by_event", {}).get("buckets", [])}
            
            # Build time series chart data
            time_series = []
            for b in aggs.get("by_time", {}).get("buckets", []):
                time_series.append({"time": b["key_as_string"], "count": b["doc_count"]})
                
            chart_data = {
                "time_series": time_series,
                "severities": [{"name": k, "value": v} for k, v in severities.items()],
                "classes": [{"name": k, "value": v} for k, v in classes.items()]
            }
        except Exception:
            total_alerts = 0
            severities = {}
            classes = {}
            events = {}
            chart_data = {}

        # 2. Fetch Threat Intel Stats
        enriched_profiles = ThreatActorProfile.objects.filter(enrichment_status="complete", is_whitelisted=False)
        total_threat_actors = enriched_profiles.count()
        critical_actors = enriched_profiles.filter(threat_level="critical").count()
        high_actors = enriched_profiles.filter(threat_level="high").count()

        # 3. Fetch Hunt Stats
        active_campaigns = HuntCampaign.objects.filter(status="active")
        total_campaigns = active_campaigns.count()
        findings_count = sum(c.findings_count for c in active_campaigns)

        # 4. Fetch Baseline Deviations
        active_deviations = BaselineDeviation.objects.filter(is_acknowledged=False)
        deviations_count = active_deviations.count()
        volume_spikes = active_deviations.filter(deviation_type="volume_spike").count()

        # 5. Compile Prompt for Qwen
        stats_summary = (
            f"SUMMARY STATISTICS FOR THE LAST {hours} HOURS:\n"
            f"- Total Anomalous Alerts detected: {total_alerts}\n"
            f"  - Severity breakdowns: {severities}\n"
            f"  - Classification types (TTPs): {classes}\n"
            f"  - Common Event Sources: {events}\n"
            f"- Threat Intelligence Profiles Active: {total_threat_actors} ({critical_actors} Critical, {high_actors} High)\n"
            f"- Active Threat Hunting Campaigns: {total_campaigns} campaigns with {findings_count} verified findings\n"
            f"- Log Baseline Anomalies: {deviations_count} unacknowledged anomalies ({volume_spikes} volume spikes)\n"
        )

        system_prompt = f"""
You are an Elite Lead Security Architect and CISO analyzing recent security telemetry.

{stats_summary}

CRITICAL WRITING RULES:
1. Write a highly professional, forensic-level security executive report. 
2. Use sophisticated, authoritative cyber language (e.g. "We observed a statistically significant standard deviation in anomalous ingress patterns"). 
3. DO NOT write like a generic AI or use phrases like "Certainly!" or "Here is the report."
4. Start immediately with a "# 🛡️ NGAO SOC Executive Daily Briefing".
5. Use markdown extensively: bolding, blockquotes for key findings, and horizontal rules to separate sections.
6. The report MUST contain the following sections:
    - **Executive Summary**: High-level impact and risk assessment.
    - **Telemetry & Alert Analysis**: Deep dive into the numbers (correlate the stats above).
    - **Threat Landscape Assessment**: Analyze the Threat Actor profiles and what they imply.
    - **Hunt & Baseline Operations**: Discuss ongoing hunt campaigns and active baseline deviations.
    - **Strategic Recommendations**: 3-5 actionable remediation steps.
7. Be highly creative, making assumptions about specific TTPs (Tactics, Techniques, and Procedures) that might align with the stats to make the report feel grounded in reality.
"""

        payload = {
            "model": QWEN_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": stats_summary}
            ],
            "max_tokens": 2000,
            "temperature": 0.3
        }

        try:
            with httpx.Client(verify=False, timeout=60.0) as client:
                res = client.post(
                    f"{QWEN_API_URL}/chat/completions",
                    headers={"Authorization": f"Bearer {QWEN_API_KEY}"},
                    json=payload
                )
                res.raise_for_status()
                report_content = res.json()["choices"][0]["message"]["content"].strip()
        except Exception as e:
            return Response({"error": f"Failed to contact Qwen AI to generate report: {str(e)}"}, status=500)

        # 6. Save the generated report
        report = DailyReport.objects.create(
            title=f"Daily Executive Security Report ({hours}h window)",
            generated_by=request.user,
            content=report_content,
            hours_covered=hours,
            chart_data=chart_data
        )

        serializer = DailyReportSerializer(report)
        return Response(serializer.data, status=201)


class DailyReportDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            report = DailyReport.objects.get(pk=pk)
            serializer = DailyReportSerializer(report)
            return Response(serializer.data)
        except DailyReport.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)

    def delete(self, request, pk):
        try:
            report = DailyReport.objects.get(pk=pk)
            report.delete()
            return Response({"status": "success", "message": "Report deleted."})
        except DailyReport.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)
