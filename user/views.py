from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .models import CustomUser
import pyotp
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from user.decorators import email_verified_required
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.hashers import make_password
from django.contrib.auth import logout
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import (
    UserRegistrationSerializer,
    UserProfileUpdateSerializer,
    UserListSerializer,
)
from auth_service.tasks import (
    send_otp_email,
    send_password_reset_link_mail,
)
# from twilio.rest import Client
from auth_service.utils import (
    get_response_schema,
    success_message,
    error_message,
    get_serializer_error_msg,
)



class UserRegistrationView(APIView):
    @swagger_auto_schema(
        operation_description="Create a new user registration",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description="Email of user."),
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description="Phone number of user."),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description="Password of user."),
                'first_name': openapi.Schema(type=openapi.TYPE_STRING, description="First name of user."),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING, description="Last name of user."),
            }
        ),
        required=['email', 'phone_number', 'password']
    )
    def post(self, request):
        """User registration API endpoint"""

        data = request.data
        serializer = UserRegistrationSerializer(data=data)

        if serializer.is_valid():

            user_data = serializer.save()

            user_data.save()

            totp = pyotp.TOTP(user_data.otp_secret, interval=300)
            otp = totp.now() 

            try:
                send_otp_email.delay(user_data.email, otp)
            except Exception as e:
                return get_response_schema(error_message('MAIL_ERROR'), {}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            return get_response_schema(success_message('REGISTRATION_EMAIL'), serializer.data, status.HTTP_201_CREATED)

        return get_response_schema(error_message('BAD_REQUEST'), get_serializer_error_msg(serializer.errors), status.HTTP_400_BAD_REQUEST)


class OTPVerificationView(APIView):
    """API to validate OTP for user email verification"""

    def get_object(self, email):

        user_data = CustomUser.objects.filter(email=email)

        if not user_data.exists():
            return None
        return user_data.first()

    @swagger_auto_schema(
        operation_description="Endpoint to validate OTP for user email verification",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description="Email of user."),
                'otp': openapi.Schema(type=openapi.TYPE_INTEGER, description="OTP to validate user's email."),
            }
        ),
        required=['email', 'otp']
    )
    def post(self, request):
        """
        Validates the OTP entered by the user.
        If the OTP is valid, the email_verified flag is set to True.
        """

        email = request.data.get('email')
        otp = request.data.get('otp')
        
        if not email or not otp:
            return get_response_schema(error_message('FIELDS_REQUIRED'), {}, status.HTTP_400_BAD_REQUEST)

        user_data = self.get_object(email)

        if user_data is None:
            return get_response_schema(error_message('USER_NOT_FOUND'), {}, status.HTTP_404_NOT_FOUND)

        totp = pyotp.TOTP(user_data.otp_secret, interval=300)

        if totp.verify(otp):

            user_data.is_email_verified = True
            user_data.save()

            return get_response_schema(success_message('OTP_VERIFIED'), {}, status.HTTP_200_OK)

        return get_response_schema(error_message('INVALID_OR_EXPIRE'), {}, status.HTTP_400_BAD_REQUEST)


class OTPResendView(APIView):
    """API to resend OTP to user email"""

    def get_object(self, email):

        user_data = CustomUser.objects.filter(email=email)

        if not user_data.exists():
            return None
        return user_data.first()

    @swagger_auto_schema(
        operation_description="Endpoint to resend OTP to user email",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description="Email of user."),
            }
        ),
        required=['email']
    )
    def post(self, request):
        """Resend OTP to the user's email."""

        email = request.data.get('email')

        if not email:
            return get_response_schema(error_message('EMAIL_REQUIRED'), {}, status.HTTP_400_BAD_REQUEST)

        user_data = self.get_object(email)

        if user_data is None:
            return get_response_schema(error_message('USER_NOT_FOUND'), {}, status.HTTP_404_NOT_FOUND)
        
        if user_data.is_email_verified == True:
            return get_response_schema(error_message('ALREADY_VERIFIED'), {}, status.HTTP_404_NOT_FOUND)

        user_data.otp_secret = pyotp.random_base32()
        user_data.save()

        totp = pyotp.TOTP(user_data.otp_secret, interval=300)
        otp = totp.now()

        try:
            send_otp_email.delay(user_data.email, otp)
        except Exception as e:
            return get_response_schema(error_message('MAIL_ERROR'), {}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return get_response_schema(success_message('OTP_RESENT'), {}, status.HTTP_200_OK)


class UserLoginView(APIView):
    """API to login user"""

    def get_object(self, phone_number):

        user_data = CustomUser.objects.filter(phone_number=phone_number)

        if not user_data.exists():
            return None
        return user_data.first()

    @swagger_auto_schema(
        operation_description="Endpoint to send OTP to user phone number",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description="Phone number of user."),
            }
        ),
        required=['phone_number']
    )
    def post(self, request):
        """Resend OTP to the user's phone."""

        phone_number = request.data.get('phone_number')

        if not phone_number:
            return get_response_schema(error_message('PHONE_NO_REQUIRED'), {}, status.HTTP_400_BAD_REQUEST)

        user_data = self.get_object(phone_number)

        if user_data is None:
            return get_response_schema(error_message('USER_NOT_FOUND'), {}, status.HTTP_404_NOT_FOUND)
        
        if user_data.is_email_verified != True:
            return get_response_schema(error_message('UN_VERIFIED'), {}, status.HTTP_400_BAD_REQUEST)

        user_data.otp_secret = pyotp.random_base32()
        user_data.save()

        totp = pyotp.TOTP(user_data.otp_secret, interval=300)
        otp = totp.now()

        try:
            send_otp_email.delay(user_data.email, otp)
        except Exception as e:
            return get_response_schema(error_message('MAIL_ERROR'), {}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return get_response_schema(success_message('OTP_SENT'), {}, status.HTTP_200_OK)


class OTPLoginVerificationView(APIView):
    """API to validate OTP for user login and generate JWT token"""

    def get_object(self, phone_number):

        user_data = CustomUser.objects.filter(phone_number=phone_number)

        if not user_data.exists():
            return None
        return user_data.first()

    @swagger_auto_schema(
        operation_description="Endpoint to validate OTP for user login and generate JWT token",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description="Phone number of user."),
                'otp': openapi.Schema(type=openapi.TYPE_INTEGER, description="OTP to validate user's phone number."),
            }
        ),
        required=[]
    )
    def post(self, request):
        """
        Validates the OTP entered by the user.
        If the OTP is valid, a JWT token is generated and returned.
        """

        phone_number = request.data.get('phone_number')
        otp = request.data.get('otp')
        
        if not phone_number or not otp:
            return get_response_schema(error_message('FIELDS_REQUIRED'), {}, status.HTTP_400_BAD_REQUEST)
        
        user_data = self.get_object(phone_number)

        if user_data.is_email_verified != True:
            return get_response_schema(error_message('UN_VERIFIED'), {}, status.HTTP_400_BAD_REQUEST)

        if user_data is None:
            return get_response_schema(error_message('USER_NOT_FOUND'), {}, status.HTTP_404_NOT_FOUND)

        totp = pyotp.TOTP(user_data.otp_secret, interval=300)

        if totp.verify(otp):

            refresh = RefreshToken.for_user(user_data)
            refresh["role"] = user_data.role
            
            user_data.save()

            return get_response_schema(success_message('LOGGED_IN'), { 'refresh': str(refresh), 'access': str(refresh.access_token) }, status.HTTP_200_OK)

        return get_response_schema(error_message('INVALID_OR_EXPIRE'), {}, status.HTTP_400_BAD_REQUEST)


class UserLogout(APIView):
    """Common logout API for all users."""

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body = openapi.Schema(
            type = openapi.TYPE_OBJECT,
            properties = {
                'refresh': openapi.Schema(type=openapi.TYPE_STRING),
            }
        )
    )
    def post(self, request):

        try:
            refresh_token = RefreshToken(request.data['refresh'])

            refresh_token.blacklist()

            return get_response_schema(success_message('LOGGED_OUT'), {}, status.HTTP_200_OK)

        except:

            return get_response_schema(error_message('INVALID_REFRESH_TOKEN'), error_message('BAD_REQUEST'), status.HTTP_401_UNAUTHORIZED)
        

class UpdateProfileView(APIView):
    """API to update user profile details (First Name, Last Name, Phone Number, Password)"""
    
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_description="End pint to update user profile.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'first_name': openapi.Schema(type=openapi.TYPE_STRING, description="First name of user."),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING, description="Last name of user."),
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description="Phone number of user."),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description="Password of user."),
            }
        ),
        required=['email', 'phone_number', 'password']
    )
    @email_verified_required
    def patch(self, request):
        user = request.user
        serializer = UserProfileUpdateSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            if "password" in request.data:
                serializer.validated_data["password"] = make_password(request.data["password"])
            
            serializer.save()
            return get_response_schema(success_message('RECORD_UPDATED'), serializer.data, status.HTTP_200_OK)
        
        return get_response_schema(error_message('BAD_REQUEST'), get_serializer_error_msg(serializer.errors), status.HTTP_400_BAD_REQUEST)
    

class UserListView(APIView):
    """API that only allows Admin users."""
    
    permission_classes = [IsAuthenticated]
    authentication_classes  = [JWTAuthentication]

    def get(self, request):
        if request.user.role != "Admin":
            return get_response_schema(error_message('PERMISSION_DENIED'), {}, status.HTTP_403_FORBIDDEN)
        
        data= CustomUser.objects.all()
        serializer = UserListSerializer(data, many=True)

        return get_response_schema(success_message('RECORD_RETRIEVED'), serializer.data, status.HTTP_200_OK)
    
    
class PasswordResetRequestView(APIView):
    """API to request a password reset by sending a reset link via email."""

    def get_object(self, email):

        user_data = CustomUser.objects.filter(email=email)

        if not user_data.exists():
            return None
        return user_data.first()

    @swagger_auto_schema(
        operation_description="Endpoint to resend OTP to user email",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description="Email of user."),
            }
        ),
        required=['email']
    )
    def post(self, request):

        email = request.data.get("email")
        if not email:
            return get_response_schema(error_message('FIELDS_REQUIRED'), {}, status=status.HTTP_400_BAD_REQUEST)
        
        user = CustomUser.objects.filter(email=email)

        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = f"http://127.0.0.1:8000/api/user/password_reset?uid={uid}&token={token}"
        
        try:
            send_password_reset_link_mail.delay(email, reset_link)        
        except Exception as e:
            return get_response_schema(error_message('MAIL_ERROR'), {}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    """API to reset the password using the token from the email link."""

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]


    def get_object(self, email):

        user_data = CustomUser.objects.filter(email=email)

        if not user_data.exists():
            return None
        return user_data.first()

    def post(self, request):
        uidb64 = request.data.get("uid")
        token = request.data.get("token")
        new_password = request.data.get("new_password")
        
        if not uidb64 or not token or not new_password:
            return get_response_schema(error_message('FIELDS_REQUIRED'), {}, status=status.HTTP_400_BAD_REQUEST)
        
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = self.get_object(uid)

        if user is None:
            return get_response_schema(error_message('USER_NOT_FOUND'), {}, status.HTTP_404_NOT_FOUND)
        
        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            return get_response_schema(error_message('INVALID_TOKEN') ,{}, status=status.HTTP_400_BAD_REQUEST)
        
        user.set_password(new_password)
        user.save()
        return get_response_schema(success_message('RECORD_UPDATED'), {}, status=status.HTTP_200_OK)


def password_reset_request(request):
    return render(request, 'request.html')


def password_reset(request):
    return render(request, 'reset.html')
