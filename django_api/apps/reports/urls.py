from django.urls import path
from .views import ReportDownloadView

urlpatterns = [
    path('', ReportDownloadView.as_view(), name='report-download'),
]
