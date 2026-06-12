import httpx
from django.conf import settings
from rest_framework.views import APIView
from django.http import StreamingHttpResponse
from .models import ReportJob

class ReportDownloadView(APIView):
    def get(self, request):
        hours = request.GET.get('hours', 24)
        
        # Save request tracking
        ReportJob.objects.create(
            requested_by=request.user,
            hours=hours,
            status='completed'  # Synchronous for now
        )
        
        with httpx.Client() as client:
            req = client.build_request("GET", f"{settings.ML_SERVICE_URL}/report", params={"hours": hours})
            r = client.send(req, stream=True)
            return StreamingHttpResponse(
                r.iter_bytes(),
                content_type=r.headers.get("content-type", "application/pdf"),
                headers={"Content-Disposition": r.headers.get("content-disposition", "")}
            )
