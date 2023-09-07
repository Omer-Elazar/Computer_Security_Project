from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.hashers import make_password
from django.db.models.signals import post_save
from django.dispatch import receiver


# Create your models here.


class CustomUserManager(BaseUserManager):
    def create_user(self, username, password, email, **extra_fields):
        user = self.model(username=username, password=make_password(password), email=email, **extra_fields)
        user.save(using=self._db)
        return user


class CustomUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=30, unique=True)
    password = models.CharField(max_length=128)
    email = models.CharField(max_length=128)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = []  # No additional fields required for registration

    # Add a field to track failed login attempts
    failed_login_attempts = models.PositiveIntegerField(default=0)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def set_password(self, raw_password):
        PasswordHistory.save_last_password(self, raw_password)
        self.password = make_password(raw_password)


class PasswordHistory(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    password_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    @classmethod
    def save_last_password(cls, user, password):
        # Save the new password in the password history
        password_hash = make_password(password)
        cls.objects.create(user=user, password_hash=password_hash)

        last_passwords = cls.objects.filter(user=user).order_by('-created_at')
        if len(last_passwords) > 10:
            last_passwords.last().delete()


# Signal to create the password history after saving a new CustomUser instance
@receiver(post_save, sender=CustomUser)
def create_password_history(sender, instance, created, **kwargs):
    if created:
        PasswordHistory.save_last_password(instance, instance.password)


class UserAccount(models.Model):
    # user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    email = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class CommonPassword(models.Model):
    password = models.CharField(max_length=128, unique=True)
