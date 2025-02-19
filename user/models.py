from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _
import pyotp
import uuid
from django.core.validators import RegexValidator


class RoleType(models.TextChoices):
    ADMIN = 'Admin', _('Admin')
    MANAGER = 'Manager', _('Manager')
    EMPLOYEE = 'Employee', _('Employee')
                             

# Function to generate OTP secret
def generate_otp_secret():
    return pyotp.random_base32()
    

class CustomUserManager(BaseUserManager):
    """Custom user manager to handle user creation"""

    def create_user(self, email, phone_number, password=None, **extra_fields):
        """Create and return a regular user"""
        if not email:
            raise ValueError("The Email field must be set.")
        if not phone_number:
            raise ValueError("The Phone Number field must be set.")

        email = self.normalize_email(email)
        user = self.model(email=email, phone_number=phone_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, phone_number, password=None, **extra_fields):
        """Create and return a superuser"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_email_verified', True)

        return self.create_user(email, phone_number, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """Custom User model integrating profile fields"""

    email = models.EmailField(unique=True, max_length=255)
    phone_number = models.CharField(
        max_length=15,
        unique=True,
        validators=[
            RegexValidator(
                regex=r'^\+?\d{10,15}$',
                message="Enter a valid phone number."
            )
        ],
    )

    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)

    role = models.CharField(choices=RoleType.choices, max_length=50, null=True, blank=True)

    otp_secret = models.CharField(max_length=32, editable=False)
    is_email_verified = models.BooleanField(default=False)
    # otp_generated_at = models.DateTimeField(null=True, blank=True)  # Timestamp of OTP generation

    reset_token = models.UUIDField(
        default=uuid.uuid4,
        null=True,
        blank=True,
        editable=False
    )

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['phone_number', 'first_name', 'last_name', 'password']

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        indexes = [
            models.Index(fields=['email', 'phone_number']),
        ]

    def __str__(self):
        return f"User id={self.id}, email={self.email}"
