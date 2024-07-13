from django.urls import include, path
from . import views
from rest_framework_simplejwt import views as jwt_views
from .views import OTPVerificationView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns =[
 path("register/", views.RegisterView.as_view(), name="user-register"),
 path("register2/", views.RegistrationView.as_view(), name="user-register"),
 path('otp-verification/',OTPVerificationView.as_view(), name='otp_verification'),
 path("login/", views.LoginView.as_view(), name="user-login"),
 path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
 path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
  path("user/details/", views.UserDetails.as_view(), name="user-details"), 
    
]