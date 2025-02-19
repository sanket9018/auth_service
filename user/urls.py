from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import (
    UserRegistrationView,
    OTPVerificationView,
    OTPResendView,
    UserLoginView,
    OTPLoginVerificationView,
    UserLogout,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    UpdateProfileView,
    UserListView,

    password_reset_request,
    password_reset,
)

urlpatterns = [

    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('v1/register/', UserRegistrationView.as_view(), name='user-register'),
    path('v1/otp-verification/', OTPVerificationView.as_view(), name='otp-verification'),
    path('v1/resend-otp/', OTPResendView.as_view(), name='resend-otp'),
    path('v1/login/', UserLoginView.as_view(), name='user-login'),
    path('v1/otp-login-verification/', OTPLoginVerificationView.as_view(), name='otp-login-verification'),
    path('v1/logout/', UserLogout.as_view(), name='user-logout'),
    path('v1/password-reset/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('v1/password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

    path('v1/update-profile/', UpdateProfileView.as_view(), name='update-profile'),
    path('v1/user-list/', UserListView.as_view(), name='user-list'),

    path('password-reset-request/', password_reset_request, name='password-reset-request'),
    path('password_reset/', password_reset, name='password_reset'),

]
