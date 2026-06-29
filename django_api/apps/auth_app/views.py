from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate, login, update_session_auth_hash
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import redirect
from django.http import HttpResponse
from rest_framework import status
import os
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

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")

        if not current_password or not new_password:
            return Response({"error": "Missing current or new password"}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(current_password):
            return Response({"error": "Incorrect current password"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        
        # Keep user logged in by updating session hash
        update_session_auth_hash(request, user)

        return Response({"success": "Password updated successfully"})

@csrf_exempt
def admin_sso_form(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user and user.is_staff:
            login(request, user)
            return redirect('/admin/')
        return HttpResponse('''
            <div style="display:flex; justify-content:center; align-items:center; height:100vh; background-color:#0a0f18; margin:0; font-family:sans-serif;">
                <h1 style="color:#ef4444; font-size:5rem; text-align:center; text-transform:uppercase; border: 5px solid #ef4444; padding: 40px; box-shadow: 0 0 50px rgba(239, 68, 68, 0.3);">Access Denied</h1>
            </div>
        ''', status=403)
    return redirect('/admin/')
