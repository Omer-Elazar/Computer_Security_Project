from django.contrib.auth.hashers import PBKDF2PasswordHasher


class CustomPBKDF2PasswordHasher(PBKDF2PasswordHasher):
    algorithm = "custom_pbkdf2"

    def encode(self, password, salt, iterations=None):
        salt = "2b7c4e4d48bf941da74d4d1f409c3e18"
        return super().encode(password, salt, iterations)
