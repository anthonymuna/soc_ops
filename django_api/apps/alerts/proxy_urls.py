from django.urls import path, re_path
from .views import MLProxyView

urlpatterns = [
    re_path(r'^(?P<path>(health|stats|train|scan|model/status|test|logs/recent))/?$', MLProxyView.as_view()),
]
