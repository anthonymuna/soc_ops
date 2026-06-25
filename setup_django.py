import os

base_dir = "django_api"

files = {
    "requirements.txt": """django==5.0.4
djangorestframework==3.15.1
djangorestframework-simplejwt==5.3.1
django-cors-headers==4.3.1
dj-database-url==2.1.0
psycopg2==2.9.9
gunicorn==22.0.0
httpx==0.27.0
elasticsearch==8.12.0
""",
    
    "Dockerfile": """FROM python:3.11-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
WORKDIR /app
RUN apt-get update && apt-get install -y gcc libpq-dev curl netcat-openbsd && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chmod +x entrypoint.sh
EXPOSE 8080
CMD ["./entrypoint.sh"]
""",

    "entrypoint.sh": """#!/bin/sh
set -e

echo "Waiting for postgres..."
while ! pg_isready -U "${POSTGRES_USER:-syndicate4}" -h "postgres" -p "5432" > /dev/null 2>&1; do
  sleep 2
done

echo "Waiting for ml_service..."
while ! curl -sf http://ml_service:8000/health > /dev/null 2>&1; do
  sleep 2
done

echo "Running migrations..."
python manage.py makemigrations auth_app alerts reports config
python manage.py migrate --noinput

echo "Creating superuser..."
if [ "$DJANGO_SUPERUSER_USERNAME" ] && [ "$DJANGO_SUPERUSER_PASSWORD" ]; then
    python manage.py createsuperuser --noinput || echo "Superuser already exists."
fi

echo "Starting Gunicorn..."
exec gunicorn syndicate4.wsgi:application --bind 0.0.0.0:8080 --workers 4
""",

    "manage.py": """#!/usr/bin/env python
import os
import sys

def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'syndicate4.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)

if __name__ == '__main__':
    main()
""",

    "syndicate4/__init__.py": "",
    "syndicate4/asgi.py": """import os
from django.core.asgi import get_asgi_application
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'syndicate4.settings')
application = get_asgi_application()
""",
    "syndicate4/wsgi.py": """import os
from django.core.wsgi import get_wsgi_application
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'syndicate4.settings')
application = get_wsgi_application()
""",

    "syndicate4/settings.py": """import os
from pathlib import Path
from datetime import timedelta
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("SECRET_KEY", "django-insecure-default-key-for-dev")
DEBUG = os.getenv("DEBUG", "False").lower() == "true"
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'apps.auth_app',
    'apps.alerts',
    'apps.reports',
    'apps.config',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'syndicate4.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'syndicate4.wsgi.application'

DATABASES = {
    'default': dj_database_url.config(
        default=os.getenv('DATABASE_URL', 'postgres://syndicate4:changeme@postgres:5432/syndicate4'),
        conn_max_age=600
    )
}

AUTH_USER_MODEL = 'auth_app.SOCUser'

AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True
STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

CORS_ALLOW_ALL_ORIGINS = True

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=8),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
}

ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://ml_service:8000")
ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
""",

    "syndicate4/urls.py": """from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('apps.auth_app.urls')),
    path('api/alerts/', include('apps.alerts.urls')),
    path('api/reports/', include('apps.reports.urls')),
    path('api/config/', include('apps.config.urls')),
    path('api/', include('apps.alerts.proxy_urls')), # stats, health, model, train, scan, logs
]
""",

    "apps/__init__.py": "",

    "apps/auth_app/__init__.py": "",
    "apps/auth_app/models.py": """from django.contrib.auth.models import AbstractUser
from django.db import models

class SOCUser(AbstractUser):
    pass
""",
    "apps/auth_app/serializers.py": """from rest_framework import serializers
from .models import SOCUser

class SOCUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = SOCUser
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_staff']
""",
    "apps/auth_app/views.py": """from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializers import SOCUserSerializer

class UserMeView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        serializer = SOCUserSerializer(request.user)
        return Response(serializer.data)
""",
    "apps/auth_app/urls.py": """from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenBlacklistView
from .views import UserMeView

urlpatterns = [
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', TokenBlacklistView.as_view(), name='token_blacklist'),
    path('me/', UserMeView.as_view(), name='user_me'),
]
""",

    "apps/alerts/__init__.py": "",
    "apps/alerts/models.py": """from django.db import models
from django.conf import settings

class AlertFeedback(models.Model):
    alert_id = models.CharField(max_length=200)
    label = models.CharField(max_length=50)
    comment = models.TextField(blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    submitted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    source = models.CharField(max_length=50, default='wazuh')

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField()
    blocked_at = models.DateTimeField(auto_now_add=True)
    blocked_by = models.CharField(max_length=100)
    reason = models.TextField()
    severity = models.CharField(max_length=20)
    is_active = models.BooleanField(default=True)
    unblocked_at = models.DateTimeField(null=True, blank=True)
""",
    "apps/alerts/serializers.py": """from rest_framework import serializers
from .models import AlertFeedback, BlockedIP

class AlertFeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertFeedback
        fields = '__all__'
""",
    "apps/alerts/views.py": """import httpx
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
        
        # We proxy to ES directly or through ml_service?
        # The instructions say: "proxy to ES + ml_service"
        # We can just fetch directly from ES.
        from datetime import datetime, timezone, timedelta
        since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        try:
            resp = es.search(
                index="syndicate4-ml-alerts",
                body={
                    "query": {"range": {"ml_detected_at": {"gte": since}}},
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
    def dispatch(self, request, *args, **kwargs):
        path = kwargs.get('path', '')
        url = f"{settings.ML_SERVICE_URL}/{path}"
        
        try:
            with httpx.Client() as client:
                req = client.build_request(request.method, url, params=request.GET.urlencode(), json=request.data if request.body else None)
                r = client.send(req)
                return Response(r.json(), status=r.status_code)
        except Exception as e:
            return Response({"error": str(e)}, status=500)
""",
    "apps/alerts/urls.py": """from django.urls import path
from .views import AlertsListView, AlertDetailView, AlertFeedbackView, AlertReportView

urlpatterns = [
    path('', AlertsListView.as_view(), name='alerts-list'),
    path('<str:pk>/', AlertDetailView.as_view(), name='alert-detail'),
    path('<str:pk>/feedback/', AlertFeedbackView.as_view(), name='alert-feedback'),
    path('<str:pk>/report/', AlertReportView.as_view(), name='alert-report'),
]
""",
    "apps/alerts/proxy_urls.py": """from django.urls import path, re_path
from .views import MLProxyView

urlpatterns = [
    re_path(r'^(?P<path>(health|stats|train|scan|model/status|test|logs/recent))/?$', MLProxyView.as_view()),
]
""",

    "apps/reports/__init__.py": "",
    "apps/reports/models.py": """from django.db import models
from django.conf import settings

class ReportJob(models.Model):
    requested_at = models.DateTimeField(auto_now_add=True)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    hours = models.IntegerField(default=24)
    status = models.CharField(max_length=20, default='pending')
    completed_at = models.DateTimeField(null=True)
""",
    "apps/reports/views.py": """import httpx
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
""",
    "apps/reports/urls.py": """from django.urls import path
from .views import ReportDownloadView

urlpatterns = [
    path('', ReportDownloadView.as_view(), name='report-download'),
]
""",

    "apps/config/__init__.py": "",
    "apps/config/models.py": """from django.db import models
from django.conf import settings

class SOCConfig(models.Model):
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
""",
    "apps/config/views.py": """from rest_framework.views import APIView
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
""",
    "apps/config/urls.py": """from django.urls import path
from .views import SOCConfigView

urlpatterns = [
    path('', SOCConfigView.as_view(), name='soc-config'),
]
"""
}

def create_files():
    for filepath, content in files.items():
        full_path = os.path.join(base_dir, filepath)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)

if __name__ == "__main__":
    create_files()
    print("Django setup completed successfully.")
