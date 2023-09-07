from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser, UserAccount


class CreateUserForm(UserCreationForm):
    email = forms.EmailField(required=True, label='Email')

    class Meta(UserCreationForm.Meta):
        model = CustomUser
        fields = ("username", "email", "password1", "password2")

    def save(self, commit=True):
        user = super(UserCreationForm, self).save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


class UserAccountForm(forms.ModelForm):
    email = forms.EmailField(required=True, label='Email')

    class Meta:
        model = UserAccount
        fields = ('name', 'email')


class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput())

    class Meta:
        fields = ('username', 'password')
