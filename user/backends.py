"""Module user.backends"""
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from user.models import User

class AuthenticateBackend(ModelBackend):
    """Authenticate User by email OR username"""

    def authenticate(self, request, username=None, password=None, **kwargs):
        """Try authenticate by login (username or email)"""

        user_model = get_user_model()

        try:
            user = user_model.objects.get(email=username)
        except user_model.DoesNotExist:
            try:
                user = User.objects.get(username=username)
            except user_model.DoesNotExist:
                return None
            else:
                user = user_model.objects.get(email=user.email)
                if user.check_password(password):
                    return user
        else:
            if user.check_password(password):
                return user

        return None
