from django.core.validators import BaseValidator
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password, check_password

from Compuer_Security_Project.models import PasswordHistory, CommonPassword
from djangoProject.password_config import *


class DigitValidator(BaseValidator):
    def __init__(self, limit_value=1):
        super().__init__(limit_value)

    @staticmethod
    def validate(password, user=None):
        if not any(char.isdigit() for char in password):
            raise ValidationError('Password must contain at least 1 digit.')

    @staticmethod
    def get_help_text():
        return 'Password must contain at least 1 digit.'


class UppercaseValidator(BaseValidator):
    def __init__(self, limit_value=1):
        super().__init__(limit_value)

    @staticmethod
    def validate(password, user=None):
        if not any(char.isupper() for char in password):
            raise ValidationError('Password must contain at least 1 upper case letter.')

    @staticmethod
    def get_help_text():
        return 'Password must contain at least 1 upper case letter.'


class LowercaseValidator(BaseValidator):
    def __init__(self, limit_value=1):
        super().__init__(limit_value)

    @staticmethod
    def validate(password, user=None):
        if not any(char.islower() for char in password):
            raise ValidationError('Password must contain at least 1 lower case letter.')

    @staticmethod
    def get_help_text():
        return 'Password must contain at least 1 lower case letter.'


class SpecialCharacterValidator(BaseValidator):
    def __init__(self, limit_value=1):
        super().__init__(limit_value)

    @staticmethod
    def validate(password, user=None):
        special_characters = r"[~\!@#\$%\^&\*\(\)_\+{}\":;'\[\]]"
        if not any(char in special_characters for char in password):
            raise ValidationError('Password must contain at least 1 special character.')

    @staticmethod
    def get_help_text():
        return 'Password must contain at least 1 special character.'


class MinLengthValidator(BaseValidator):
    def __init__(self, limit_value=1, min_length=10):
        super().__init__(limit_value)
        self.min_length = min_length

    def validate(self, password, user=None):
        if len(password) < self.min_length:
            raise ValidationError(f'Password must contain at least {self.min_length} characters.')

    def get_help_text(self):
        return f'Password must contain at least {self.min_length} characters.'


class PasswordHistoryValidator(BaseValidator):
    def __init__(self, limit_value=1):
        super().__init__(limit_value)

    @staticmethod
    def validate(password, user=None):
        if user:
            prev_pw = PasswordHistory.objects.filter(user=user).order_by('-created_at')[:PASSWORD_HISTORY_COUNT]
            if any(check_password(password, prev.password_hash)for prev in prev_pw):
                raise ValidationError("This password has been used in the user's recent password history.")

    @staticmethod
    def get_help_text():
        return "This password has been used in the user's recent password history."


class CommonPasswordValidator(BaseValidator):
    def __init__(self, limit_value=1):
        super().__init__(limit_value)

    @staticmethod
    def validate(password, user=None):
        common_passwords = CommonPassword.objects.values_list('password', flat=True)

        if password.lower() in common_passwords:
            raise ValidationError('This password is too common.')

    @staticmethod
    def get_help_text():
        return 'The password is too common.'


class CustomPasswordValidator(BaseValidator):
    def __init__(self, limit_value=1):
        super().__init__(limit_value)
        self.validators = []

        if NUMERIC_REQUIRED:
            self.validators.append(DigitValidator())
        if UPPERCASE_REQUIRED:
            self.validators.append(UppercaseValidator())
        if LOWERCASE_REQUIRED:
            self.validators.append(LowercaseValidator())
        if SPECIAL_CHARACTER_REQUIRED:
            self.validators.append(SpecialCharacterValidator())
        if MIN_LENGTH > 0:
            self.validators.append(MinLengthValidator(min_length=MIN_LENGTH))
        if PASSWORD_HISTORY_COUNT > 0:
            self.validators.append(PasswordHistoryValidator())
        if COMMON_PASSWORDS_ENABLED:
            self.validators.append(CommonPasswordValidator())

    def validate(self, password, user=None):
        for validator in self.validators:
            validator.validate(password, user=user)

    def get_help_text(self):
        help_texts = [validator.get_help_text() for validator in self.validators]
        return '\n'.join(help_texts)
