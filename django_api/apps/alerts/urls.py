from django.urls import path
from .views import AlertsListView, AlertDetailView, AlertFeedbackView, AlertReportView

urlpatterns = [
    path('', AlertsListView.as_view(), name='alerts-list'),
    path('<str:pk>/', AlertDetailView.as_view(), name='alert-detail'),
    path('<str:pk>/feedback/', AlertFeedbackView.as_view(), name='alert-feedback'),
    path('<str:pk>/report/', AlertReportView.as_view(), name='alert-report'),
]
