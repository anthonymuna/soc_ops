import os
import time
import httpx
from datetime import datetime, timezone, timedelta
from django.utils import timezone as dj_tz
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError
from elasticsearch import Elasticsearch, NotFoundError

from .models import HuntQuery, HuntHypothesis, HuntCampaign, HuntFinding, AgentBaseline, BaselineDeviation
from .serializers import (
    HuntQuerySerializer, HuntHypothesisSerializer, HuntCampaignSerializer, 
    HuntFindingSerializer, AgentBaselineSerializer, BaselineDeviationSerializer
)

ES_HOST = os.environ.get("ES_HOST", "http://elasticsearch:9200")
es = Elasticsearch(ES_HOST)

QWEN_API_URL = os.environ.get("QWEN_API_URL", "https://10.101.7.72/v1").rstrip('/')
QWEN_API_KEY = os.environ.get("QWEN_API_KEY", "57be7935b6f361750802cd937f3252d21ce14eab9b8acfcf9a40e53e7cf13486")
QWEN_MODEL   = os.environ.get("QWEN_MODEL", "qwen-military-advisor-q8_0_v2.gguf")


def inject_time_range_to_query(query_body: dict, time_range: str) -> dict:
    """Helper to inject date range filters into raw ES queries."""
    if not time_range or time_range == "all":
        return query_body

    # Convert time_range shorthand to timedelta
    now = datetime.now(timezone.utc)
    if time_range == "1h":
        since = now - timedelta(hours=1)
    elif time_range == "24h":
        since = now - timedelta(days=1)
    elif time_range == "7d":
        since = now - timedelta(days=7)
    elif time_range == "30d":
        since = now - timedelta(days=30)
    else:
        # Fallback to 24h
        since = now - timedelta(days=1)

    time_filter = {"range": {"ml_detected_at": {"gte": since.isoformat()}}}

    # Ensure query has structure
    if "query" not in query_body:
        query_body["query"] = {"bool": {}}
    
    q = query_body["query"]
    if "bool" not in q:
        # Wrap existing query in bool
        original_q = q.copy()
        query_body["query"] = {"bool": {"must": [original_q]}}
        q = query_body["query"]

    if "filter" not in q["bool"]:
        q["bool"]["filter"] = []
    elif not isinstance(q["bool"]["filter"], list):
        q["bool"]["filter"] = [q["bool"]["filter"]]

    q["bool"]["filter"].append(time_filter)
    return query_body


class WorkbenchView(APIView):
    """Execute raw or visual builder query on Elasticsearch."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        index = request.data.get("index", "syndicate4-ml-alerts")
        query_body = request.data.get("query", {})
        time_range = request.data.get("time_range", "24h")
        size = min(int(request.data.get("size", 200)), 1000)

        # Restrict indices allowed for safety
        if index not in ["syndicate4-ml-alerts", "syndicate4-logs-*"]:
            raise ValidationError({"index": "Invalid or restricted index selector."})

        # Inject timeframe filter
        query_body = inject_time_range_to_query(query_body, time_range)
        query_body["size"] = size

        start_time = time.time()
        try:
            r = es.search(index=index, body=query_body)
            hits = [h["_source"] for h in r["hits"]["hits"]]
            # Attach doc ID to hits for reference
            for idx, h in enumerate(r["hits"]["hits"]):
                hits[idx]["_id"] = h["_id"]

            return Response({
                "hits": hits,
                "total": r["hits"]["total"]["value"] if isinstance(r["hits"]["total"], dict) else r["hits"]["total"],
                "took_ms": int((time.time() - start_time) * 1000),
                "index": index
            })
        except NotFoundError:
            return Response({"hits": [], "total": 0, "took_ms": 0, "index": index})
        except Exception as e:
            return Response({"error": f"Elasticsearch query failed: {str(e)}"}, status=400)


class SavedQueriesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = HuntQuery.objects.filter(is_active=True)
        serializer = HuntQuerySerializer(qs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = HuntQuerySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)


class SavedQueryDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            q = HuntQuery.objects.get(pk=pk, is_active=True)
            serializer = HuntQuerySerializer(q)
            return Response(serializer.data)
        except HuntQuery.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)

    def put(self, request, pk):
        try:
            q = HuntQuery.objects.get(pk=pk, is_active=True)
            serializer = HuntQuerySerializer(q, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=400)
        except HuntQuery.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)

    def delete(self, request, pk):
        try:
            q = HuntQuery.objects.get(pk=pk, is_active=True)
            q.is_active = False  # Soft delete
            q.save()
            return Response({"status": "success", "message": "Query deleted."})
        except HuntQuery.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)


class RunSavedQueryView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            q = HuntQuery.objects.get(pk=pk, is_active=True)
            time_range = request.data.get("time_range", "24h")
            size = min(int(request.data.get("size", 200)), 1000)

            query_body = q.es_query.copy()
            query_body = inject_time_range_to_query(query_body, time_range)
            query_body["size"] = size

            start_time = time.time()
            try:
                r = es.search(index=q.es_index, body=query_body)
                hits = [h["_source"] for h in r["hits"]["hits"]]
                for idx, h in enumerate(r["hits"]["hits"]):
                    hits[idx]["_id"] = h["_id"]

                hit_count = r["hits"]["total"]["value"] if isinstance(r["hits"]["total"], dict) else r["hits"]["total"]

                # Update query metrics
                q.run_count += 1
                q.last_run_at = dj_tz.now()
                q.last_hit_count = hit_count
                q.save()

                return Response({
                    "hits": hits,
                    "total": hit_count,
                    "took_ms": int((time.time() - start_time) * 1000),
                    "index": q.es_index
                })
            except Exception as e:
                return Response({"error": f"Elasticsearch execution failed: {str(e)}"}, status=400)

        except HuntQuery.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)


class HypothesesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = HuntHypothesis.objects.all()
        tactic = request.query_params.get("tactic")
        severity = request.query_params.get("severity")

        if tactic:
            qs = qs.filter(tactic=tactic)
        if severity:
            qs = qs.filter(severity=severity)

        serializer = HuntHypothesisSerializer(qs, many=True)
        return Response(serializer.data)


class RunHypothesisView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            hyp = HuntHypothesis.objects.get(pk=pk)
            time_range = request.data.get("time_range", "24h")
            agent_filter = request.data.get("agent")
            size = min(int(request.data.get("size", 200)), 1000)

            query_body = hyp.es_query.copy()
            query_body = inject_time_range_to_query(query_body, time_range)
            query_body["size"] = size

            # Inject agent filter if specified
            if agent_filter:
                agent_clause = {"term": {"agent_name.keyword": agent_filter}}
                if "query" not in query_body:
                    query_body["query"] = {"bool": {}}
                if "must" not in query_body["query"]["bool"]:
                    query_body["query"]["bool"]["must"] = []
                query_body["query"]["bool"]["must"].append(agent_clause)

            start_time = time.time()
            try:
                r = es.search(index="syndicate4-ml-alerts", body=query_body)
                hits = [h["_source"] for h in r["hits"]["hits"]]
                for idx, h in enumerate(r["hits"]["hits"]):
                    hits[idx]["_id"] = h["_id"]

                hit_count = r["hits"]["total"]["value"] if isinstance(r["hits"]["total"], dict) else r["hits"]["total"]

                # Update playbook metrics
                hyp.run_count += 1
                hyp.last_run_at = dj_tz.now()
                hyp.last_hit_count = hit_count
                hyp.save()

                return Response({
                    "hits": hits,
                    "total": hit_count,
                    "took_ms": int((time.time() - start_time) * 1000),
                    "index": "syndicate4-ml-alerts"
                })
            except Exception as e:
                return Response({"error": f"Elasticsearch execution failed: {str(e)}"}, status=400)

        except HuntHypothesis.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)


class CampaignsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = HuntCampaign.objects.all()
        serializer = HuntCampaignSerializer(qs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = HuntCampaignSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(lead_analyst=request.user)
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)


class CampaignDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            campaign = HuntCampaign.objects.get(pk=pk)
            serializer = HuntCampaignSerializer(campaign)
            return Response(serializer.data)
        except HuntCampaign.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)

    def put(self, request, pk):
        try:
            campaign = HuntCampaign.objects.get(pk=pk)
            serializer = HuntCampaignSerializer(campaign, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=400)
        except HuntCampaign.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)


class FindingsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            campaign = HuntCampaign.objects.get(pk=pk)
            findings = campaign.findings.all()
            serializer = HuntFindingSerializer(findings, many=True)
            return Response(serializer.data)
        except HuntCampaign.DoesNotExist:
            return Response({"detail": "Campaign not found."}, status=404)

    def post(self, request, pk):
        try:
            campaign = HuntCampaign.objects.get(pk=pk)
            serializer = HuntFindingSerializer(data=request.data)
            if serializer.is_valid():
                finding = serializer.save(campaign=campaign, created_by=request.user)
                # Increment campaign outcome stats
                campaign.findings_count = campaign.findings.count()
                if finding.verdict == "false_positive":
                    campaign.false_positives += 1
                campaign.save()
                return Response(serializer.data, status=201)
            return Response(serializer.errors, status=400)
        except HuntCampaign.DoesNotExist:
            return Response({"detail": "Campaign not found."}, status=404)


class BaselinesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = AgentBaseline.objects.all()
        serializer = AgentBaselineSerializer(qs, many=True)
        return Response(serializer.data)


class DeviationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = BaselineDeviation.objects.filter(is_acknowledged=False)
        agent = request.query_params.get("agent")
        severity = request.query_params.get("severity")

        if agent:
            qs = qs.filter(agent_name=agent)
        if severity:
            qs = qs.filter(severity=severity)

        serializer = BaselineDeviationSerializer(qs, many=True)
        return Response(serializer.data)


class AcknowledgeDeviationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            dev = BaselineDeviation.objects.get(pk=pk)
            dev.is_acknowledged = True
            dev.acknowledged_by = request.user
            dev.save()
            return Response({"status": "success", "message": f"Deviation {pk} acknowledged."})
        except BaselineDeviation.DoesNotExist:
            return Response({"detail": "Not found."}, status=404)


class AIHuntView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        prompt = request.data.get("prompt")
        if not prompt:
            raise ValidationError({"prompt": "No prompt specified."})

        system_prompt = (
            "You are a threat hunting expert for NGAO SOC, a Security Operations Center "
            "monitoring networks across East Africa (Kenya, Uganda, Tanzania, Rwanda).\n\n"
            "The analyst has described a hunt they want to perform. Generate:\n"
            "1. An Elasticsearch query (ES DSL) for index \"syndicate4-ml-alerts\"\n"
            "2. Human-readable hunt steps\n"
            "3. MITRE ATT&CK techniques to focus on\n"
            "4. Suggested follow-up actions\n\n"
            "Available ES fields: src_ip, dst_ip, event_type, ml_severity, ml_rf_class "
            "(dos/probe/r2l/u2r/normal), ml_rf_confidence, ml_detected_at, agent_name, "
            "mitre_techniques, detection_method, connector (wazuh/fortisiem/umbrella)\n\n"
            "Return JSON ONLY. No markdown wrapper, no conversational preamble. Follow this schema exactly:\n"
            "{\n"
            "  \"es_query\": { ...valid ES DSL... },\n"
            "  \"hunt_steps\": [\"step 1\", \"step 2\", ...],\n"
            "  \"mitre_techniques\": [\"T1021.001\", ...],\n"
            "  \"reasoning\": \"brief explanation of the hunt approach\",\n"
            "  \"follow_up\": \"suggested next hunt if this returns results\"\n"
            "}"
        )

        payload = {
            "model": QWEN_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 1000,
            "temperature": 0.1
        }

        try:
            with httpx.Client(verify=False, timeout=45) as client:
                res = client.post(
                    f"{QWEN_API_URL}/chat/completions",
                    headers={"Authorization": f"Bearer {QWEN_API_KEY}"},
                    json=payload
                )
                res.raise_for_status()
                content = res.json()["choices"][0]["message"]["content"].strip()
                content = content.replace("```json", "").replace("```", "").strip()
                import json
                parsed = json.loads(content)
                return Response(parsed)
        except Exception as e:
            return Response({"error": f"Qwen generation failed: {str(e)}"}, status=500)


class AISaveHuntView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        name = request.data.get("name")
        es_query = request.data.get("es_query")
        description = request.data.get("description", "")
        mitre = request.data.get("mitre_techniques", [])

        if not name or not es_query:
            raise ValidationError({"error": "Name and es_query fields are required."})

        q = HuntQuery.objects.create(
            name=name,
            es_query=es_query,
            description=description,
            mitre_techniques=mitre,
            created_by=request.user
        )

        serializer = HuntQuerySerializer(q)
        return Response(serializer.data, status=201)
