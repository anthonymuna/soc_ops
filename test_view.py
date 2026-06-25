import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'syndicate4.settings')
django.setup()
from django.test import RequestFactory
from apps.alerts.views import MLProxyView

request = RequestFactory().get('/api/stats')
view = MLProxyView.as_view()
try:
    response = view(request, path='stats')
    print("Response Status:", response.status_code)
    try:
        print("Response JSON:", response.json())
    except:
        print("Response Content:", response.content)
except Exception as e:
    import traceback
    traceback.print_exc()
