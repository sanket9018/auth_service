from functools import wraps
from rest_framework.response import Response
from rest_framework import status


def email_verified_required(view_func):
    """
    Decorator to check if the user's email is verified before allowing access.
    """
    @wraps(view_func)
    def wrapper(self, request, *args, **kwargs):
        if not request.user.is_email_verified:
            return Response(
                {"error": "Email verification is required to perform this action."},
                status=status.HTTP_403_FORBIDDEN
            )
        return view_func(self, request, *args, **kwargs)
    
    return wrapper
