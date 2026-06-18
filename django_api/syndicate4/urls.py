from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from django.contrib.auth import logout
from django.http import HttpResponse
import os

def admin_login_denied(request):
    return HttpResponse('''
        <div style="display:flex; justify-content:center; align-items:center; height:100vh; background-color:#0a0f18; margin:0; font-family:sans-serif;">
            <h1 style="color:#ef4444; font-size:5rem; text-align:center; text-transform:uppercase; border: 5px solid #ef4444; padding: 40px; box-shadow: 0 0 50px rgba(239, 68, 68, 0.3);">Access Denied</h1>
        </div>
    ''', status=403)

def custom_admin_logout(request):
    logout(request)
    frontend_url = os.getenv("FRONTEND_URL", "http://10.104.4.68")
    return redirect(frontend_url)

urlpatterns = [
    path('admin/login/', admin_login_denied),
    path('admin/logout/', custom_admin_logout),
    path('admin/', admin.site.urls),
    path('api/auth/', include('apps.auth_app.urls')),
    path('api/alerts/', include('apps.alerts.urls')),
    path('api/reports/', include('apps.reports.urls')),
    path('api/config/', include('apps.config.urls')),
    path('api/', include('apps.alerts.proxy_urls')), # stats, health, model, train, scan, logs
]
