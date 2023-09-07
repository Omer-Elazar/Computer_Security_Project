"""
URL configuration for djangoProject project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from Compuer_Security_Project.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', landing, name='landing'),
    path('login/', login_view, name='login'),
    path('register/', register, name='register'),
    path('system_screen/', system_screen, name='system_screen'),
    path('change_password/', change_password, name='change_password'),
    path('forgot_password/', forgot_password, name='forgot_password'),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('reset_password/', reset_password, name='reset_password'),
    path('logout/', logout_view, name='logout'),
]