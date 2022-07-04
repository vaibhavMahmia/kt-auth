from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

# Create your models here.

# Customer_api
class UserManager(BaseUserManager):
    def create_superuser(self, email, name, mobile, pincode, state, city, address, account_type, account_category, tc, password=None):
        """
        Creates and saves a superuser with the given email,name and password.
        """
        user = self.create_customer(
            email,
            password=password,
            name=name,
            mobile=mobile,
            pincode=pincode,
            state=state,
            city=city,
            address=address,
            account_type=account_type,
            account_category=account_category,
            tc=tc
        )

        user.is_admin = True
        user.save(using=self._db)
        return user

    def create_customer(self, email, name, mobile, pincode, state, city, address, account_type, account_category, tc, password=None, password2=None):
        """
        Creates and saves a customer with the given email,name and password.
        """
        if not email:
            raise ValueError('Please enter the email address!!!')

        customer = self.model(
            email=self.normalize_email(email),
            name=name,
            mobile=mobile,
            pincode=pincode,
            state=state,
            city=city,
            address=address,
            account_type=account_type,
            account_category=account_category,
            tc=tc
        )

        customer.set_password(password)
        customer.save(using=self._db)
        return customer

    def create_dealer(self, email, name, mobile, pincode, state, city, address, account_type, tc, password=None, password2=None):
        """
        Creates and saves a dealer with the given email,name and password.
        """
        if not email:
            raise ValueError('Please enter the email address!!!')

        dealer = self.model(
            email=self.normalize_email(email),
            name=name,
            mobile=mobile,
            pincode=pincode,
            state=state,
            city=city,
            address=address,
            account_type=account_type,
            tc=tc
        )

        dealer.set_password(password)
        dealer.save(using=self._db)
        return dealer


class Customer(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='Email',
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=200)
    kt_id=models.CharField(max_length=50, default="KTCP{self.id}")
    mobile = models.CharField(max_length=10)
    pincode =models.CharField(max_length=6)
    state = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    address = models.CharField(max_length=200)
    account_type = models.CharField(max_length=50)
    account_category = models.CharField(max_length=50)
    tc = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'mobile', 'pincode', 'state', 'city', 'address', 'account_type', 'account_category', 'tc']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the customer have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the customer have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin


# Dealer_api

class Dealer(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='Email',
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=200)
    kt_id=models.CharField(max_length=50, default="KTDK{self.id}")
    mobile = models.CharField(max_length=10)
    pincode =models.CharField(max_length=6)
    state = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    address = models.CharField(max_length=200)
    account_type = models.CharField(max_length=50)
    tc = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'mobile', 'pincode', 'state', 'city', 'address', 'account_type', 'tc']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the dealer have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the dealer have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the dealer a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin
