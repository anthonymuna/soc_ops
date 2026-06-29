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
                }
            })
            total_alerts = r["hits"]["total"]["value"] if isinstance(r["hits"]["total"], dict) else r["hits"]["total"]
            aggs = r.get("aggregations", {})
            severities = {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])}
            classes = {b["key"]: b["doc_count"] for b in aggs.get("by_class", {}).get("buckets", [])}
            events = {b["key"]: b["doc_count"] for b in aggs.get("by_event", {}).get("buckets", [])}
        except Exception:
            total_alerts = 0
            severities = {}
            classes = {}
            events = {}

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

        system_prompt = (
            "You are the Chief Information Security Officer (CISO) and Principal Incident Responder for NGAO SOC, "
            "protecting critical enterprise networks across East Africa (Kenya, Uganda, Tanzania, Rwanda).\n\n"
            "Generate a highly detailed, rigorous, and technical Executive Security Posture Report based on the provided stats.\n\n"
            "CRITICAL WRITING RULES:\n"
            "1. DO NOT write a generic or high-level summary. Use formal, professional cybersecurity terminology.\n"
            "2. Avoid simple lists of numbers; instead, write deep analytical paragraphs explaining what the metrics indicate regarding attacker behavior and network risk.\n"
            "3. Explicitly map observed behaviors to the MITRE ATT&CK framework (e.g. T1110 for Brute Force, T1021 for Lateral Movement, T1046 for port scanning).\n"
            "4. In the Recommendations section, provide concrete, actionable security instructions (e.g. specific firewall rule changes, network segmentation configurations, SSH key rotation policies, multi-factor VPN setups, and Wazuh decoder/alert tuning rules).\n"
            "5. Do not include conversational remarks, preambles, or postscripts. Start directly with the title.\n\n"
            "FOLLOW THIS STRUCTURE EXACTLY:\n\n"
            "# Executive Security Posture Report - [Insert Current Date]\n"
            "## 1. Executive Summary & Posture Assessment\n"
            "(Provide a comprehensive overview of the threat landscape, risk profile, and overall posture. Explain what the active metrics signify for the organization's business continuity.)\n\n"
            "## 2. Ingest Telemetry & Incident Analysis\n"
            "(Analyze the alert telemetry. Detail the anomalous alert categories [R2L, DoS, Probe, U2R] and severities. Discuss active threat campaigns and vector patterns.)\n\n"
            "## 3. Threat Intelligence Profile & Active Adversaries\n"
            "(Evaluate the enriched threat actor profiles, critical IP reputations, TOR nodes, anonymous proxies, and geo-origin distributions.)\n\n"
            "## 4. Threat Hunting Baselines & Anomaly Deviations\n"
            "(Analyze active hunt campaigns, findings, and unacknowledged deviations. Discuss log volume spikes, off-hours access, and unexpected ports/countries discovered during behavioral baselining.)\n\n"
            "## 5. Strategic Recommendations & Technical Action Items\n"
            "(Provide highly technical, concrete action items. Specify actual configuration parameters, rule changes, segmentation policies, and next steps for the security engineering team.)"
        )

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
            hours_covered=hours
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
