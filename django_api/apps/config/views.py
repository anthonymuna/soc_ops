from rest_framework.views import APIView
from rest_framework.response import Response
from .models import SOCConfig

class SOCConfigView(APIView):
    def get(self, request):
        configs = SOCConfig.objects.all()
        return Response({c.key: c.value for c in configs})

    def patch(self, request):
        if not request.user.is_staff:
            return Response({"detail": "Admin only."}, status=403)
            
        for key, value in request.data.items():
            conf, created = SOCConfig.objects.get_or_create(key=key)
            conf.value = str(value)
            conf.updated_by = request.user
            conf.save()
            
        return Response({"status": "updated"})
