import random
import pyotp
from django.contrib.auth import update_session_auth_hash, login, authenticate, logout
from django.contrib.auth.hashers import make_password
from django.db import connection
from django.shortcuts import render, redirect
from django.contrib.auth.forms import PasswordChangeForm, PasswordResetForm, SetPasswordForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from Compuer_Security_Project.forms import CreateUserForm, UserAccountForm, LoginForm
from django.core.mail import send_mail

from djangoProject.settings import get_custom_user_model
from .models import CustomUser, UserAccount

from django.views.decorators.http import require_http_methods


# Create your views here.
User = get_custom_user_model()


def landing(request):
    return redirect('login')


# ---------------------------register and login-----------------------------------


def register(request):
    form = CreateUserForm()

    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            email = form.cleaned_data['email']
            # Execute raw SQL query to create and save the user
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO compuer_security_project_customuser "
                    "(is_superuser, is_active, is_staff, failed_login_attempts, password, email, username) "
                    "VALUES (False, True, True, 0, '"+make_password(password)+"', '"+email+"', '"+username+"')"
                )

            messages.success(request, 'Registration successful. You can now login.')
            return redirect('login')

    return render(request, 'register.html', {'form': form})


def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        print(form.errors)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')

            # Execute raw SQL query to authenticate user
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM compuer_security_project_customuser WHERE username = '"
                    ""+username+"' AND password = '"+make_password(password)+"'"
                )
                user_row = cursor.fetchone()

            if user_row is not None:
                # Log in the user
                user = CustomUser.objects.get(pk=user_row[0])
                login(request, user)
                messages.success(request, 'Login successful.')
                return redirect('system_screen')
            else:
                messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()

    return render(request, 'login.html', {'form': form})

# ---------------------------------------------------------------------------------


def logout_view(request):
    logout(request)
    return redirect('login')


@login_required(login_url='login')
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Update the session to prevent the user from being logged out
            messages.success(request, 'Password changed successfully.')
            return redirect('system_screen')
    else:
        form = PasswordChangeForm(request.user)

    return render(request, 'change_password.html', {'form': form})


@login_required(login_url='login')
def system_screen(request):
    accounts = UserAccount.objects.raw("SELECT * FROM compuer_security_project_useraccount")
    username = request.user.username

    if request.method == 'POST':
        form = UserAccountForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['name']
            email = form.cleaned_data['email']
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO compuer_security_project_useraccount "
                    "(email, name) VALUES ('"+email+"', '"+name+"')"
                )

            messages.success(request, form.cleaned_data['name']+' Added successfully')
            return redirect('system_screen')
    else:
        form = UserAccountForm()

    context = {
        'username': username,
        'accounts': accounts,
        'form': form,
    }
    return render(request, 'system_screen.html', context)


# ----------------------------forgot password------------------------------------------------
def generate_otp_key():
    return pyotp.random_base32(length=32)  # Generate a 32-character base32 key (160 bits)


def generate_otp(user_hotp, counter):
    return user_hotp.at(counter)


def send_otp_to_user(user, otp_key, counter):
    user_hotp = pyotp.HOTP(otp_key)
    otp = generate_otp(user_hotp, counter)

    subject = 'Your One-Time Password (OTP)'
    message = f'Your OTP is: {otp}'
    from_email = 'your_email@example.com'  # Update with your email address
    recipient_list = [user.email]

    send_mail(subject, message, from_email, recipient_list)


def forgot_password(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            try:
                user = User.objects.get(email=email)
                otp_key = generate_otp_key()
                counter = random.randint(0, 99)  # Initialize the counter with a random value (adjust as needed)

                send_otp_to_user(user, otp_key, counter)

                request.session['otp_key'] = otp_key
                request.session['counter'] = counter  # Store the counter in the session

                request.session['user_email'] = email

                return redirect('verify_otp')
            except User.DoesNotExist:
                messages.error(request, 'User with this email does not exist.')
    else:
        form = PasswordResetForm()

    return render(request, 'forgot_password.html', {'form': form})


@login_required(login_url='login')
def reset_password(request):
    if not request.session['otp_verified']:
        return redirect('verify_otp')

    if request.method == 'POST':
        form = SetPasswordForm(User.objects.get(email=request.session.get('user_email')), request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Password reset successful. You can now login with your new password.')
            return redirect('login')
    else:
        form = SetPasswordForm(request.user)

    return render(request, 'reset_password.html', {'form': form})


def verify_otp(request):
    otp_key = request.session.get('otp_key')
    counter = request.session.get('counter', 0)
    user_hotp = pyotp.HOTP(otp_key)

    if request.method == 'POST':
        user_otp = request.POST.get('otp')

        # Verify the OTP against the stored key and counter
        if user_hotp.verify(user_otp, counter=counter):
            request.session['otp_verified'] = True

            # If the user is authenticated, get the user from the session
            if request.user.is_authenticated:
                user = request.user

            # If the user is not authenticated, fetch the user from the database using the email
            else:
                user_email = request.session.get('user_email')
                try:
                    user = User.objects.get(email=user_email)
                except User.DoesNotExist:
                    messages.error(request, 'User does not exist.')
                    return redirect('verify_otp')

            # Authenticate the user
            user.is_active = True
            user.failed_login_attempts = 0
            user.save()
            user = authenticate(request, username=user.username, password=user.password)
            if user is not None:
                login(request, user)

            return redirect('reset_password')
        else:
            context = {'message': 'Invalid OTP. Please try again.'}
            return render(request, 'verify_otp.html', context)

    context = {}
    return render(request, 'verify_otp.html', context)

# ---------------------------------------------------------------------------------
