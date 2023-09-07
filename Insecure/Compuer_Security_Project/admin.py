from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser


# Register your models here.

class CustomUserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'is_active', 'is_staff')
    list_filter = ('is_active', 'is_staff')


# Register the CustomUser model using the CustomUserAdmin class
admin.site.register(CustomUser, CustomUserAdmin)