import email
from .models import Customer, Dealer
from .serializers import CustomerRegistrationSerializer, SendDealerPasswordResetEmailSerializer, CustomerLoginSerializer, DealerRegistrationSerializer, DealerLoginSerializer, SendCustomerPasswordResetEmailSerializer, CustomerPasswordResetSerializer, DealerPasswordResetSerializer
from rest_framework.response import Response
from rest_framework import status,generics
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
# generating the token manually


def get_tokens_for_user(Customer):
    refresh = RefreshToken.for_user(Customer)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


def get_tokens_for_user(Dealer):
    refresh = RefreshToken.for_user(Dealer)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# Customer view


class CustomerRegistrationView(APIView):

    def post(self, request, format=None):
        serializer = CustomerRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            Customer = serializer.save()
            #token = get_tokens_for_user(Customer)
            user_data = serializer.data

            token = RefreshToken.for_user(Customer).access_token
            current_site = get_current_site(request).domain
            relativeLink = reverse('email_verify')
           
            absurl = f'http://{current_site}{relativeLink}?token={str(token)}'
            email_body = f'Hi {Customer.name} use the link to verify ur account {absurl}'
            data = {
                'body': email_body,
                'subject': 'verify ur email',
                'to': Customer.email
            }
            #Util.send_email(data)
            print(f"\x1b[31m {absurl}")
            return Response({'token': str(token), 'msg': 'Registration successfully done!!'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmail(generics.GenericAPIView):
    def get(self, request):
        token = request.GET.get('token')
        try:
           payload = jwt.decode(token,settings.SECRET_KEY)
           user = Customer.objects.get(id=payload['user_id'])
           user.is_verified = True
           user.save()
           return Response({'msg': 'verified'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'link expired'}, status=status.HTTP_400_BAD_REQUEST)
class VerifyEmailD(generics.GenericAPIView):
    def get(self, request):
        token = request.GET.get('token')
        try:
           payload = jwt.decode(token,settings.SECRET_KEY)
           user = Dealer.objects.get(id=payload['user_id'])
           user.is_verified = True
           user.save()
           return Response({'msg': 'verified'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'link expired'}, status=status.HTTP_400_BAD_REQUEST)
class CustomerLoginView(APIView):

    def post(self, request, format=None):
        serializer = CustomerLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            customer = authenticate(email=email, password=password)
            if customer is None:
                return Response({'msg': 'Login successfully done!!'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors': {'non_field_errors': ['Email or password is not valid']}}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendCustomerPasswordResetEmailView(APIView):
    def post(self, request, format=None):
        serializer = SendCustomerPasswordResetEmailSerializer(
            data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password reset link send. Please check your email...'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomerPasswordResetView(APIView):
    def post(self, request, uid, token, format=None):
        serializer = CustomerPasswordResetSerializer(
            data=request.data, context={'uid': uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password reset Successfully!!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Dealer view


class DealerRegistrationView(APIView):

    def post(self, request, format=None):
        serializer = DealerRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            Dealer = serializer.save()
            token = RefreshToken.for_user(Dealer).access_token
            current_site = get_current_site(request).domain
            relativeLink = reverse('email_verify')
           
            absurl = f'http://{current_site}{relativeLink}?token={str(token)}'
            email_body = f'Hi {Dealer.name} use the link to verify ur account {absurl}'
            data = {
                'body': email_body,
                'subject': 'verify ur email',
                'to': Dealer.email
            }
            #Util.send_email(data)
            print(f"\x1b[31m {absurl}")
            return Response({'token': str(token), 'msg': 'Registration successfully done!!'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DealerLoginView(APIView):

    def post(self, request, format=None):
        serializer = DealerLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is None:
                return Response({'msg': 'Login successfully done!!'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors': {'non_field_errors': ['Email or password is not valid']}}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendDealerPasswordResetEmailView(APIView):
    def post(self, request, format=None):
        serializer = SendDealerPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password reset link send. Please check your email...'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DealerPasswordResetView(APIView):
    def post(self, request, uid, token, format=None):
        serializer = DealerPasswordResetSerializer(
            data=request.data, context={'uid': uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password reset Successfully!!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
