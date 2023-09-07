from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from djangoProject.settings import get_custom_user_model
from .models import CustomUser
from djangoProject.password_config import MAX_FAILED_LOGIN_ATTEMPTS

User = get_custom_user_model()


class BlockAfterFailedAttemptsBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        user = super().authenticate(request, username=username, password=password, **kwargs)

        if user is None:
            # User login failed; increment failed login attempts
            try:
                user = User.objects.get(username=username)
                user.failed_login_attempts += 1
                user.save()

                # Check if the user has exceeded the maximum allowed failed login attempts
                if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
                    # Block the user
                    user.is_active = False
                    user.save()
                    raise ValidationError('Too many failed login attempts. Your account is temporarily blocked.')
            except User.DoesNotExist:
                pass

        else:
            # User login succeeded; reset failed login attempts
            if user.failed_login_attempts > 0:
                user.failed_login_attempts = 0
                user.save()

        return user


class CustomUserBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = CustomUser.objects.get(username=username)
            if user.check_password(password):
                return user
        except CustomUser.DoesNotExist:
            return None
