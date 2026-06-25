from django.urls import path
from .views import TriageListView, TriageApproveView, TriageDismissView, ChatProxyView, HealthProxyView

urlpatterns = [
    path('triage/', TriageListView.as_view(), name='brain-triage-list'),
    path('triage/<str:triage_id>/approve/', TriageApproveView.as_view(), name='brain-triage-approve'),
    path('triage/<str:triage_id>/dismiss/', TriageDismissView.as_view(), name='brain-triage-dismiss'),
    path('chat/', ChatProxyView.as_view(), name='brain-chat'),
    path('health/', HealthProxyView.as_view(), name='brain-health'),
]
