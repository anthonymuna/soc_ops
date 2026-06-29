from django.urls import path
from .views import ReportDownloadView, DailyReportListView, DailyReportDetailView

urlpatterns = [
    path('', ReportDownloadView.as_view(), name='report-download'),
    path('daily/', DailyReportListView.as_view(), name='daily-report-list'),
    path('daily/<int:pk>/', DailyReportDetailView.as_view(), name='daily-report-detail'),
]
