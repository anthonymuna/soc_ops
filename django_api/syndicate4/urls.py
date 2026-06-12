from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('apps.auth_app.urls')),
    path('api/alerts/', include('apps.alerts.urls')),
    path('api/reports/', include('apps.reports.urls')),
    path('api/config/', include('apps.config.urls')),
    path('api/', include('apps.alerts.proxy_urls')), # stats, health, model, train, scan, logs
]
