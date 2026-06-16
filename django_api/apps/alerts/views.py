import httpx
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.http import StreamingHttpResponse, JsonResponse
from elasticsearch import Elasticsearch, NotFoundError
from .models import AlertFeedback

es = Elasticsearch(settings.ES_HOST)

class AlertsListView(APIView):
    def get(self, request):
        limit = int(request.GET.get('limit', 50))
        minutes = int(request.GET.get('minutes', 60))
        connector = request.GET.get('connector')
        
        from datetime import datetime, timezone, timedelta
        since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        
        must_clauses = [{"range": {"ml_detected_at": {"gte": since}}}]
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
                return Response(r.json(), status=r.status_code)
        except Exception as e:
            return Response({"error": str(e)}, status=500)

    def get(self, request, *args, **kwargs):
        return self.handle_request(request, kwargs.get('path', ''))

    def post(self, request, *args, **kwargs):
        return self.handle_request(request, kwargs.get('path', ''))

class PredictiveAnalysisView(APIView):
    def get(self, request):
        limit = int(request.GET.get('limit', 150))
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
            "model": "Qwen/Qwen2.5-3B-Instruct",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 1500
        }
        
        try:
            with httpx.Client(verify=False) as client:
                res = client.post(
                    "https://10.101.7.72/v1/chat/completions",
                    headers={"Authorization": "Bearer 57be7935b6f361750802cd937f3252d21ce14eab9b8acfcf9a40e53e7cf13486"},
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
    def get(self, request):
        import json
        import geoip2.webservice
        import geoip2.errors
        from datetime import datetime, timezone, timedelta
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        
        try:
            resp = es.search(
                index="syndicate4-ml-alerts",
                body={
                    "query": {"range": {"ml_detected_at": {"gte": since}}},
                    "size": 100,
                    "sort": [{"ml_detected_at": {"order": "desc"}}],
                },
            )
            alerts = [h["_source"] for h in resp["hits"]["hits"]]
        except NotFoundError:
            alerts = []

        if not alerts:
            return Response({"intelligence": []})

        # Group by IP
        ip_data = {}
        for a in alerts:
            src = a.get('src_ip')
            if not src or src in ("unknown", "0.0.0.0", ""):
                continue
            if src not in ip_data:
                ip_data[src] = {"count": 0, "attack_classes": set(), "mitre_techniques": set()}
            ip_data[src]["count"] += 1
            ac = a.get("ml_rf_class")
            if ac:
                ip_data[src]["attack_classes"].add(ac)
            mitre = a.get("mitre_techniques", [])
            if isinstance(mitre, list):
                for m in mitre:
                    ip_data[src]["mitre_techniques"].add(m)

        if not ip_data:
            return Response({"intelligence": []})

        import os
        account_id = int(os.environ.get('MAXMIND_ACCOUNT_ID', '1363804'))
        license_key = os.environ.get('MAXMIND_LICENSE_KEY', '')
        
        # Initialize GeoLite Client
        geo_client = geoip2.webservice.Client(account_id, license_key, host='geolite.info')

        prompt_lines = ["Assess the threat level for these source IPs. Return a JSON array ONLY.\n"]
        for ip, d in ip_data.items():
            location = "Unknown Location"
            try:
                response = geo_client.city(ip)
                city = response.city.name
                country = response.country.name
                if city and country:
                    location = f"{city}, {country}"
                elif country:
                    location = country
            except geoip2.errors.GeoIP2Error:
                pass
            except Exception:
                pass
                
            d['location'] = location

            classes = list(d["attack_classes"])
            mitre = list(d["mitre_techniques"])
            prompt_lines.append(f"IP: {ip} | location: {location} | count: {d['count']} | attack_classes: {classes} | MITRE: {mitre}")

        prompt = "\n".join(prompt_lines)
        
        system_prompt = (
            "For each of these source IPs and their attack patterns, assess their "
            "threat level (low/medium/high/critical), likely attacker type "
            "(opportunistic/targeted/APT), and recommended defensive action. "
            "MITRE techniques observed are listed. Reply as JSON array ONLY: "
            "[{'ip':'...', 'location':'...', 'count':..., 'threat_level':'...', 'attacker_type':'...', "
            "'mitre_techniques':[...], 'recommendation':'...'}]"
        )

        payload = {
            "model": "Qwen/Qwen2.5-3B-Instruct",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 2000
        }
        
        try:
            with httpx.Client(verify=False) as client:
                res = client.post(
                    "https://10.101.7.72/v1/chat/completions",
                    headers={"Authorization": "Bearer 57be7935b6f361750802cd937f3252d21ce14eab9b8acfcf9a40e53e7cf13486"},
                    json=payload,
                    timeout=45
                )
                res.raise_for_status()
                data = res.json()
                content = data['choices'][0]['message']['content'].strip()
                
                if content.startswith("```json"):
                    content = content[7:]
                elif content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                    
                intelligence_array = json.loads(content.strip())
                return Response({"intelligence": intelligence_array})
        except Exception as e:
            return Response({"intelligence": [{"ip": "ERROR", "count": 0, "threat_level": "Critical", "attacker_type": "System Error", "mitre_techniques": ["Network Failure"], "recommendation": f"Failed to reach Qwen AI endpoint (10.101.7.72). Details: {str(e)}"}]})
