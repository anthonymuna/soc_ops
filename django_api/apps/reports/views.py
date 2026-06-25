import httpx
from django.conf import settings
from rest_framework.views import APIView
from django.http import HttpResponse
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
        
        with httpx.Client(timeout=60.0) as client:
            r = client.get(f"{settings.ML_SERVICE_URL}/report", params={"hours": hours})
            return HttpResponse(
                r.content,
                content_type=r.headers.get("content-type", "application/pdf"),
                headers={"Content-Disposition": r.headers.get("content-disposition", "")}
            )
