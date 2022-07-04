from django.urls import path, include
from accounts.views import *

urlpatterns = [
    path('customers/register/', CustomerRegistrationView.as_view(), name='cregister'),
    path('customers/email_verify/', VerifyEmail.as_view(), name='email_verify'),
    path('customers/login/', CustomerLoginView.as_view(), name='clogin'),
    path('customers/send-reset-password-email/',
         SendCustomerPasswordResetEmailView.as_view(), name='csend-reset-password-email'),
    path('customers/reset-password/<uid>/<token>/',
         CustomerPasswordResetView.as_view(), name='creset-password'),
    path('dealers/register/', DealerRegistrationView.as_view(), name='dregister'),
    path('dealers/email_verify/', VerifyEmailD.as_view(), name='email_verify'),
    path('dealers/login/', DealerLoginView.as_view(), name='dlogin'),
    path('dealers/send-reset-password-email/',
         SendDealerPasswordResetEmailView.as_view(), name='dsend-reset-password-email'),
    path('dealers/reset-password/<uid>/<token>/',
         DealerPasswordResetView.as_view(), name='dreset-password'),
]
