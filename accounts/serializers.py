import re
from ast import Pass
from unittest.util import _MAX_LENGTH
from xml.dom import ValidationErr
from rest_framework import serializers
from .models import Customer, Dealer
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util

# Customer Serializers


class CustomerRegistrationSerializer(serializers.ModelSerializer):
    # This is because we need confirm password field in this as well
    password2 = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = Customer
        fields = ['email', 'name', 'mobile', 'pincode', 'state', 'city', 'address', 'account_type', 'account_category', 'tc', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

# Validations

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        password2 = attrs.get('password2')
        # Email Validation
        k = 0
        if len(email) >= 12:
            if email[0].isalpha():
                if ("@" in email) and (email.count("@") == 1):
                    if (email[-9] == "g") and (email[-8] == "m") and (email[-7] == "a") and (email[-6] == "i") and (email[-5] == "l"):
                        if (email[-4] == "."):
                            for i in email:
                                if i == i.isspace():
                                    k = 1
                                elif i.isdigit():
                                    continue
                                elif i == "_" or i == "." or i == "@":
                                    continue
                        if k == 1:
                            raise serializers.ValidationError(
                                "Please enter a valid email address!!")
                    else:
                        raise serializers.ValidationError(
                            "Please enter a valid email address!!")
                else:
                    raise serializers.ValidationError(
                        "Please enter a valid email address!!")
            else:
                raise serializers.ValidationError(
                    "Please enter a valid email address!!")
        else:
            raise serializers.ValidationError(
                "Please enter a valid email address!!")

        # Password Validation
        flag = 0
        if not re.search('[a-z]', password):
            flag = 1
        if not re.search('[0-9]', password):
            flag = 1
        if not re.search('[A-Z]', password):
            flag = 1
        if not re.search('[$@!#]', password):
            flag = 1
        if len(password) < 8:
            flag = 1

        if (flag == 1):
            raise serializers.ValidationError(
                "Password must match the given criteria!!!")

        # Password and confirm password validation

        if password != password2:
            raise serializers.ValidationError(
                "Password and confirm password!!!")
        return attrs

    def create(self, validate_data):
        return Customer.objects.create_customer(**validate_data)


class CustomerLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = Customer
        fields = ['email', 'password']


class SendCustomerPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=250)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if Customer.objects.filter(email=email).exists():
            user = Customer.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded UID', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password Reset Token', token)
            link = 'http://localhost:8000/api/customers/reset-password/'+uid+'/'+token
            print('Password Reset link', link)
            # send email
            body = 'Click the link to reset your password-> '+link
            data = {
                'subject': 'Reset Your Password',
                'body': body,
                'to_email': user.email
            }
            Util.send_email(data)
            return attrs
        else:
            raise ValidationErr("You are not registered user!")


class CustomerPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=250, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(
        max_length=250, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError(
                    "Password and Confirm Password doesn't match!")
            id = smart_str(urlsafe_base64_decode(uid))
            user = Customer.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError('Token is not Valid or Expired!')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as Identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationError('Token is not Valid or Expired!')


# Dealer Serializers


class DealerRegistrationSerializer(serializers.ModelSerializer):
    # This is because we need confirm password field in this as well
    password2 = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = Dealer
        fields = ['email', 'name', 'mobile', 'pincode', 'state', 'city', 'address', 'account_type', 'tc', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

# Validations

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        password2 = attrs.get('password2')

        # Email Validation
        k = 0
        if len(email) >= 12:
            if email[0].isalpha():
                if ("@" in email) and (email.count("@") == 1):
                    if (email[-9] == "g") and (email[-8] == "m") and (email[-7] == "a") and (email[-6] == "i") and (email[-5] == "l"):
                        if (email[-4] == "."):
                            for i in email:
                                if i == i.isspace():
                                    k = 1
                                elif i.isdigit():
                                    continue
                                elif i == "_" or i == "." or i == "@":
                                    continue
                        if k == 1:
                            raise serializers.ValidationError(
                                "Please enter a valid email address!!")
                    else:
                        raise serializers.ValidationError(
                            "Please enter a valid email address!!")
                else:
                    raise serializers.ValidationError(
                        "Please enter a valid email address!!")
            else:
                raise serializers.ValidationError(
                    "Please enter a valid email address!!")
        else:
            raise serializers.ValidationError(
                "Please enter a valid email address!!")

        # Password Validation
        flag = 0
        if not re.search('[a-z]', password):
            flag = 1
        if not re.search('[0-9]', password):
            flag = 1
        if not re.search('[A-Z]', password):
            flag = 1
        if not re.search('[$@!#]', password):
            flag = 1
        if len(password) < 8:
            flag = 1

        if (flag == 1):
            raise serializers.ValidationError(
                "Password must match the given criteria!!!")

        # Password and confirm password validation
        if password != password2:
            raise serializers.ValidationError(
                "Password and confirm password must match!!!")
        return attrs

    def create(self, validate_data):
        return Dealer.objects.create_dealer(**validate_data)


class DealerLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = Dealer
        fields = ['email', 'password']


class SendDealerPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=250)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if Dealer.objects.filter(email=email).exists():
            user = Dealer.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded UID', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password Reset Token', token)
            link = 'http://localhost:8000/api/customers/reset-password/'+uid+'/'+token
            print('Password Reset link', link)
            # send email
            body = 'Click the link to reset your password-> '+link
            data = {
                'subject': 'Reset Your Password',
                'body': body,
                'to_email': user.email
            }
            Util.send_email(data)
            return attrs
        else:
            raise ValidationErr("You are not registered user!")


class DealerPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=250, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(
        max_length=250, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError(
                    "Password and Confirm Password doesn't match!")
            id = smart_str(urlsafe_base64_decode(uid))
            user = Dealer.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError('Token is not Valid or Expired!')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as Identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationError('Token is not Valid or Expired!')
