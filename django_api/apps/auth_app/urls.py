from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenBlacklistView
from .views import UserMeView, admin_sso_form, ChangePasswordView

urlpatterns = [
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('admin-sso/', admin_sso_form, name='admin_sso'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', TokenBlacklistView.as_view(), name='token_blacklist'),
    path('me/', UserMeView.as_view(), name='user_me'),
    path('password/change/', ChangePasswordView.as_view(), name='change_password'),
]
