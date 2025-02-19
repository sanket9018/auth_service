from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from user.models import CustomUser
import pyotp


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Customize JWT Token to include the user's role."""

    def validate(self, attrs):
        data = super().validate(attrs)  # Get the default token data
        data['role'] = self.user.role  # Add the user role to the token payload
        return data


class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'role']


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser  
        fields = [
            'email', 
            'phone_number',  
            'password', 
            'first_name', 
            'last_name'
        ]
        extra_kwargs = {
            'password': {
                'write_only': True
            }
        }

    def create(self, validated_data):
        # Remove password from validated_data to set it separately
        password = validated_data.pop('password')

        # Create the user and generate OTP secret
        user = CustomUser(**validated_data)
        user.set_password(password)  # Properly hash the password
        user.otp_secret = pyotp.random_base32()  # Generate OTP secret here
        user.save()

        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            'first_name', 
            'last_name', 
            'email'
        ]


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile details"""

    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'phone_number', 'password']
        extra_kwargs = {
            'password': {'write_only': True, 'required': False},
        }
