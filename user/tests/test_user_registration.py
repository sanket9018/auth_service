import pytest
import pyotp
from rest_framework.test import APIClient
from rest_framework import status
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth.hashers import check_password
from unittest.mock import patch, ANY  
from rest_framework_simplejwt.tokens import RefreshToken
from user.models import CustomUser


@pytest.mark.django_db
class TestUserRegistrationView:

    @pytest.fixture
    def api_client(self):
        return APIClient()

    @pytest.fixture
    def valid_payload(self):
        return {
            "email": "test@example.com",
            "phone_number": "1234567890",
            "password": "testpassword",
            "first_name": "Test",
            "last_name": "User"
        }

    @pytest.fixture
    def invalid_payload(self):
        return {
            "email": "",
            "phone_number": "",
            "password": "",
            "first_name": "",
            "last_name": ""
        }

    @pytest.fixture
    def duplicate_user(self, valid_payload):
        """Fixture to create a user with the same email before the test runs."""
        return CustomUser.objects.create_user(
            email=valid_payload["email"],
            phone_number=valid_payload["phone_number"],
            password=valid_payload["password"],
            first_name=valid_payload["first_name"],
            last_name=valid_payload["last_name"],
        )

    def test_user_registration_success(self, api_client, valid_payload):
        url = reverse('user-register')
        response = api_client.post(url, valid_payload, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert CustomUser.objects.filter(email=valid_payload['email']).exists()


    def test_user_registration_failure(self, api_client, invalid_payload):

        url = reverse('user-register')
        response = api_client.post(url, invalid_payload, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert not CustomUser.objects.filter(email=invalid_payload['email']).exists()

    def test_user_registration_failure_missing_fields(self, api_client, invalid_payload):
        url = reverse('user-register')
        response = api_client.post(url, invalid_payload, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data["results"]["detail"]

    def test_user_registration_failure_duplicate_email(self, api_client, valid_payload, duplicate_user):
        """Test registration failure when an email is already taken"""
        url = reverse('user-register')
        response = api_client.post(url, valid_payload, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data["results"]["detail"]


@pytest.mark.django_db
class TestOTPVerificationView:

    @pytest.fixture
    def api_client(self):
        return APIClient()

    @pytest.fixture
    def user_with_otp(self):
        """Fixture to create a user with an OTP secret"""
        otp_secret = pyotp.random_base32()
        user = CustomUser.objects.create_user(
            email="test@example.com",
            phone_number="+1234567890",
            password="securepassword",
            first_name="Test",
            last_name="User",
            otp_secret=otp_secret,
        )
        return user

    def test_otp_verification_success(self, api_client, user_with_otp):
        """Test OTP verification success with a valid OTP"""
        totp = pyotp.TOTP(user_with_otp.otp_secret, interval=300)
        otp = totp.now()  # Generate a valid OTP

        url = reverse('otp-verification')
        response = api_client.post(url, {"email": user_with_otp.email, "otp": otp}, format="json")

        assert response.status_code == status.HTTP_200_OK
        user_with_otp.refresh_from_db()
        assert user_with_otp.is_email_verified is True

    def test_otp_verification_failure_invalid_otp(self, api_client, user_with_otp):
        """Test OTP verification failure with an invalid OTP"""
        invalid_otp = "123456"  # Random invalid OTP

        url = reverse('otp-verification')
        response = api_client.post(url, {"email": user_with_otp.email, "otp": invalid_otp}, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "OTP is in-valid or expired" in response.data["message"]

    def test_otp_verification_failure_expired_otp(self, api_client, user_with_otp):
        """Test OTP verification failure due to expired OTP"""

        totp = pyotp.TOTP(user_with_otp.otp_secret, interval=300)
        expired_otp = totp.now()  # Generate OTP, but it's expired

        url = reverse('otp-verification')
        response = api_client.post(url, {"email": user_with_otp.email, "otp": expired_otp}, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert "OTP verified successfully" in response.data["message"]

    def test_otp_verification_failure_missing_fields(self, api_client):
        """Test OTP verification failure when email or OTP is missing"""
        url = reverse('otp-verification')

        response = api_client.post(url, {"email": "", "otp": ""}, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        response = api_client.post(url, {"email": "test@example.com"}, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        response = api_client.post(url, {"otp": "123456"}, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_otp_verification_failure_user_not_found(self, api_client):
        """Test OTP verification failure when the user does not exist"""
        url = reverse('otp-verification')
        response = api_client.post(url, {"email": "notfound@example.com", "otp": "123456"}, format="json")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "User not found." in response.data["message"]


@pytest.mark.django_db
class TestUserLoginView:

    @pytest.fixture
    def api_client(self):
        return APIClient()

    @pytest.fixture
    def user(self):
        """Fixture to create a verified user."""
        return CustomUser.objects.create_user(
            email="testuser@example.com",
            phone_number="+1234567890",
            password="Test@1234",
            first_name="Test",
            last_name="User",
            is_email_verified=True,
        )

    from unittest.mock import patch, ANY

    def test_login_otp_sent_success(self, api_client, user):
        """Test sending OTP successfully for a verified user."""
        url = reverse("user-login")
        data = {"phone_number": user.phone_number}

        with patch("user.views.send_otp_email.delay") as mock_send_otp:
            response = api_client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "OTP sent successfully"
        mock_send_otp.assert_called_once_with(user.email, ANY)  # Allow any OTP value

    def test_login_failure_user_not_found(self, api_client):
        """Test login failure when the user is not found."""
        url = reverse("user-login")
        data = {"phone_number": "+0000000000"}  # Non-existent phone number

        response = api_client.post(url, data, format="json")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.data["message"] == "User not found."

    def test_login_failure_unverified_user(self, api_client):
        """Test login failure when the user's email is not verified."""
        unverified_user = CustomUser.objects.create_user(
            email="unverified@example.com",
            phone_number="+1111111111",
            password="Test@1234",
            first_name="Test",
            last_name="User",
            is_email_verified=False,
        )

        url = reverse("user-login")
        data = {"phone_number": unverified_user.phone_number}

        response = api_client.post(url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data["message"] == "Please verify you self."


@pytest.mark.django_db
class TestUserLogoutView:

    @pytest.fixture
    def api_client(self):
        from rest_framework.test import APIClient
        return APIClient()


    @pytest.fixture
    def authenticated_user(self, api_client):
        """Fixture to create and authenticate a user with an access token."""
        user = CustomUser.objects.create_user(
            email="testuser@example.com",
            phone_number="+1234567890",
            password="Test@1234",
            first_name="Test",
            last_name="User",
        )

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)  # Get access token from refresh

        return {
            "user": user,
            "access_token": access_token,  # Include access token
            "refresh_token": str(refresh),
        }

    def test_logout_success(self, api_client, authenticated_user):
        """Test successful logout with a valid access token."""
        url = reverse("user-logout")

        # Set access token in headers
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {authenticated_user["access_token"]}')
        
        response = api_client.post(url, {"refresh": authenticated_user["refresh_token"]}, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "User has been logged out successfully."


@pytest.mark.django_db
class TestUpdateProfileView:

    @pytest.fixture
    def api_client(self):
        return APIClient()

    @pytest.fixture
    def authenticated_user(self, api_client):
        """Fixture to create and authenticate a user."""
        user = CustomUser.objects.create_user(
            email="testuser@example.com",
            phone_number="+1234567890",
            password="Test@1234",
            first_name="Test",
            last_name="User",
            is_email_verified=True,  
        )
        api_client.force_authenticate(user=user)
        return {"user": user}

    def test_update_profile_success(self, api_client, authenticated_user):
        """Test successful profile update."""
        url = reverse("update-profile")
        updated_data = {
            "first_name": "UpdatedFirst",
            "last_name": "UpdatedLast",
            "phone_number": "+0987654321",
            "password": "NewPassword@123",
        }

        response = api_client.patch(url, updated_data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["message"] == "The record has been updated successfully."

        authenticated_user["user"].refresh_from_db()
        assert authenticated_user["user"].first_name == "UpdatedFirst"
        assert authenticated_user["user"].last_name == "UpdatedLast"
        assert authenticated_user["user"].phone_number == "+0987654321"
        assert check_password("NewPassword@123", authenticated_user["user"].password) is True

    def test_update_profile_failure_invalid_data(self, api_client, authenticated_user):
        """Test profile update failure due to invalid data."""

        url = reverse("update-profile")
        invalid_data = {
            "first_name": "",  
            "phone_number": "invalid-phone", 
        }

        response = api_client.patch(url, invalid_data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Bad request." in response.data["message"]


@pytest.mark.django_db
def test_admin_can_retrieve_user_list():
    """Test that an admin user can retrieve the list of users successfully."""
    api_client = APIClient()

    admin_user = CustomUser.objects.create_user(
        email="admin@example.com",
        phone_number="+1234567890",
        password="Admin@1234",
        first_name="Admin",
        last_name="User",
        role="Admin"
    )

    api_client.force_authenticate(user=admin_user)

    url = reverse("user-list")  
    response = api_client.get(url)

    print("Response Data:", response.data)  

    assert response.status_code == status.HTTP_200_OK

    assert "message" in response.data, "Response is missing 'message' key"
    assert response.data["message"] == "The record has been retrieved successfully."

    