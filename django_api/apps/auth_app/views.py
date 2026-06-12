from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializers import SOCUserSerializer

class UserMeView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        serializer = SOCUserSerializer(request.user)
        return Response(serializer.data)
        
    def patch(self, request):
        if 'visible_cards' in request.data:
            request.user.visible_cards = request.data['visible_cards']
            request.user.save()
        serializer = SOCUserSerializer(request.user)
        return Response(serializer.data)
