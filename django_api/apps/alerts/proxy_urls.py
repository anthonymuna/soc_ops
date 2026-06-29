from django.urls import path, re_path
from .views import MLProxyView, AdvisoryFeedView, MapDataView

urlpatterns = [
    re_path(r'^(?P<path>(health|stats|train|scan|model/status|test|logs/recent))/?$', MLProxyView.as_view()),
    path('feeds/advisories/', AdvisoryFeedView.as_view(), name='advisory_feed'),
    path('map-data/', MapDataView.as_view(), name='map_data'),
]
