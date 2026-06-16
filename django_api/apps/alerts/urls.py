from django.urls import path
from .views import AlertsListView, AlertDetailView, AlertFeedbackView, AlertReportView, PredictiveAnalysisView

urlpatterns = [
    path('', AlertsListView.as_view(), name='alerts-list'),
    path('predictive-analysis/', PredictiveAnalysisView.as_view(), name='predictive-analysis'),
    path('<str:pk>/', AlertDetailView.as_view(), name='alert-detail'),
    path('<str:pk>/feedback/', AlertFeedbackView.as_view(), name='alert-feedback'),
    path('<str:pk>/report/', AlertReportView.as_view(), name='alert-report'),
]
