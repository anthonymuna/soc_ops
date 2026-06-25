from django.urls import path
from .views import SOCConfigView

urlpatterns = [
    path('', SOCConfigView.as_view(), name='soc-config'),
]
