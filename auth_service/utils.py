from rest_framework.response import Response
from django.conf import settings


def get_response_schema(message, result, status_code):
    """Customize the response for API"""

    return Response({
        'message': message,
        'results': result,
        'status': status_code,
    }, status=status_code)


def success_message(message_key):
    """Map success messages based on the API behavior"""

    data = {
        'OTP_VERIFIED': 'OTP verified successfully',
        'OTP_SENT': 'OTP sent successfully',
        'OTP_RESENT': 'OTP re-sent successfully',
        'REGISTRATION_EMAIL': "Account created successfully. Please verify your account by checking the OTP sent to your email.",
        'LOGGED_OUT': "User has been logged out successfully.",
        'LOGGED_IN': 'Logged in successfully.',
        'VALID_TOKEN': 'The token provided is valid.',

        'ORGANIZATION_REGISTERED': 'The organization has been registered successfully.',

        'RECORD_RETRIEVED': 'The record has been retrieved successfully.',
        'USER_REGISTERED': 'The user has been created successfully.',
        'RECORD_CREATED': 'The record has been created successfully.',
        'RECORD_UPDATED': 'The record has been updated successfully.',
        'RECORD_DELETED': 'The record has been deleted successfully.',
    }

    return data.get(message_key)


def error_message(message_key):
    """Map error messages based on the API behavior"""

    data = {
        'MAIL_ERROR': 'Failed to send email.',
        'FIELDS_REQUIRED': 'All fields are required',
        'UN_VERIFIED': 'Please verify you self.',
        'ALREADY_VERIFIED': 'You account is already verified.',
        'PHONE_NO_REQUIRED': 'Please provide your phone number.',
        'EMAIL_REQUIRED': 'Please provide your email address.',
        'INVALID_OR_EXPIRE': 'OTP is in-valid or expired',
        'PRODUCT_NOT_AVAILABLE': 'Product not available ( 0 Quantity )',
        'ORGANIZATION_REGISTRATION': 'Something went wrong during organization registration',
        'BAD_REQUEST': 'Bad request.',
        'PERMISSION_DENIED': 'You do not have permission to access this feature.',
        'USER_NOT_FOUND': 'User not found.',
        'DATA_NOT_FOUND': 'Data not found.',
        'INVALID_TOKEN': 'Token is invalid or expired. Please try again.',
        'UNAUTHORIZED': 'Invalid credentials.',
        'INVALID_REFRESH_TOKEN': 'Refresh token is invalid or expired. Please try again.',
    }

    return data.get(message_key)


def get_serializer_error_msg(error): 

    return {settings.REST_FRAMEWORK["NON_FIELD_ERRORS_KEY"]: error}
