import httpx
import logging
from django.conf import settings
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from apps.alerts.models import PendingAction
from apps.alerts.serializers import PendingActionSerializer

logger = logging.getLogger("django-brain-views")

class TriageListView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        pending_actions = PendingAction.objects.all().order_by('-created_at')
        serializer = PendingActionSerializer(pending_actions, many=True)
        return Response(serializer.data)

class TriageApproveView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, triage_id):
        try:
            pending_action = PendingAction.objects.get(triage_id=triage_id)
        except PendingAction.DoesNotExist:
            return Response({"success": False, "message": f"Pending action with triage_id '{triage_id}' not found."}, status=404)
            
        pending_action.status = 'approved'
        pending_action.reviewed_by = request.user
        pending_action.reviewed_at = timezone.now()
        pending_action.save()
        
        # Forward execution to ngao_brain
        brain_url = f"{settings.BRAIN_SERVICE_URL.rstrip('/')}/execute/{triage_id}"
        headers = {}
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header:
            headers['Authorization'] = auth_header
            
        try:
            with httpx.Client() as client:
                resp = client.post(brain_url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    return Response(resp.json())
                else:
                    return Response({
                        "success": False,
                        "message": f"ngao_brain service returned status {resp.status_code}: {resp.text}"
                    }, status=resp.status_code)
        except Exception as e:
            logger.error(f"Failed to contact ngao_brain: {e}")
            return Response({
                "success": False,
                "message": f"Failed to contact ngao_brain service: {str(e)}"
            }, status=500)

class TriageDismissView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, triage_id):
        try:
            pending_action = PendingAction.objects.get(triage_id=triage_id)
        except PendingAction.DoesNotExist:
            return Response({"success": False, "message": f"Pending action with triage_id '{triage_id}' not found."}, status=404)
            
        pending_action.status = 'dismissed'
        pending_action.reviewed_by = request.user
        pending_action.reviewed_at = timezone.now()
        pending_action.save()
        
        serializer = PendingActionSerializer(pending_action)
        return Response({
            "success": True,
            "message": "Action successfully dismissed.",
            "data": serializer.data
        })

class ChatProxyView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        brain_url = f"{settings.BRAIN_SERVICE_URL.rstrip('/')}/chat"
        headers = {}
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header:
            headers['Authorization'] = auth_header
            
        try:
            with httpx.Client() as client:
                resp = client.post(brain_url, json=request.data, headers=headers, timeout=30)
                if resp.status_code == 200:
                    return Response(resp.json())
                else:
                    return Response({
                        "success": False,
                        "message": f"ngao_brain chat returned status {resp.status_code}: {resp.text}"
                    }, status=resp.status_code)
        except Exception as e:
            logger.error(f"Failed to contact ngao_brain chat: {e}")
            return Response({
                "success": False,
                "message": f"Failed to contact ngao_brain chat service: {str(e)}"
            }, status=500)

class HealthProxyView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        brain_url = f"{settings.BRAIN_SERVICE_URL.rstrip('/')}/health"
        headers = {}
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header:
            headers['Authorization'] = auth_header
            
        try:
            with httpx.Client() as client:
                resp = client.get(brain_url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    return Response(resp.json())
                else:
                    return Response({
                        "success": False,
                        "message": f"ngao_brain health returned status {resp.status_code}: {resp.text}"
                    }, status=resp.status_code)
        except Exception as e:
            logger.error(f"Failed to contact ngao_brain health: {e}")
            return Response({
                "success": False,
                "message": f"Failed to contact ngao_brain health service: {str(e)}"
            }, status=500)
