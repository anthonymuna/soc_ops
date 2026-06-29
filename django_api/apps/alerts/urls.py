from django.urls import path
from .views import (
    AlertsListView, AlertDetailView, AlertFeedbackView, AlertReportView, 
    PredictiveAnalysisView, ThreatIntelligenceView, ThreatActorDetailView, 
    WhitelistIPView, TriggerEnrichmentView, ThreatIntelStatsView
)

urlpatterns = [
    path('', AlertsListView.as_view(), name='alerts-list'),
    path('predictive-analysis/', PredictiveAnalysisView.as_view(), name='predictive-analysis'),
    path('threat-intelligence/', ThreatIntelligenceView.as_view(), name='threat-intelligence'),
    path('threat-intelligence/stats/', ThreatIntelStatsView.as_view(), name='threat-intel-stats'),
    path('threat-intelligence/enrich/', TriggerEnrichmentView.as_view(), name='trigger-enrichment'),
    path('threat-intelligence/<str:ip>/', ThreatActorDetailView.as_view(), name='threat-actor-detail'),
    path('threat-intelligence/<str:ip>/whitelist/', WhitelistIPView.as_view(), name='whitelist-ip'),
    path('<str:pk>/', AlertDetailView.as_view(), name='alert-detail'),
    path('<str:pk>/feedback/', AlertFeedbackView.as_view(), name='alert-feedback'),
    path('<str:pk>/report/', AlertReportView.as_view(), name='alert-report'),
]
