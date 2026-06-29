from django.urls import path
from .views import (
    WorkbenchView, SavedQueriesView, SavedQueryDetailView, RunSavedQueryView,
    HypothesesView, RunHypothesisView, CampaignsView, CampaignDetailView,
    FindingsView, BaselinesView, DeviationsView, AcknowledgeDeviationView,
    AIHuntView, AISaveHuntView
)

urlpatterns = [
    path('workbench/run/',                WorkbenchView.as_view()),
    path('queries/',                      SavedQueriesView.as_view()),
    path('queries/<int:pk>/',             SavedQueryDetailView.as_view()),
    path('queries/<int:pk>/run/',         RunSavedQueryView.as_view()),
    path('hypotheses/',                   HypothesesView.as_view()),
    path('hypotheses/<int:pk>/run/',      RunHypothesisView.as_view()),
    path('campaigns/',                    CampaignsView.as_view()),
    path('campaigns/<int:pk>/',           CampaignDetailView.as_view()),
    path('campaigns/<int:pk>/findings/',  FindingsView.as_view()),
    path('baselines/',                    BaselinesView.as_view()),
    path('deviations/',                   DeviationsView.as_view()),
    path('deviations/<int:pk>/acknowledge/', AcknowledgeDeviationView.as_view()),
    path('ai/generate/',                  AIHuntView.as_view()),
    path('ai/save/',                      AISaveHuntView.as_view()),
]
