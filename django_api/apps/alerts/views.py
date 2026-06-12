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
