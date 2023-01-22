from django.urls import path
from account.views import *
urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepwd/', UserChangePWView.as_view(), name='profile'),
    path('send-reset-pwd-email/', SendPWDResetEmailView.as_view(), name='send-reset-pwd-email'),
    path('reset-pwd/<uid>/<token>/', UserResetPWDView.as_view(), name='reset-pwd'),
]
