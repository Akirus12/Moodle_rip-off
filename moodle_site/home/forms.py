from django import forms
from django.contrib.auth.forms import AuthenticationForm, UsernameField, UserCreationForm


class LoginForm(AuthenticationForm):
    """Authentication form with Tailwind-friendly classes."""

    username = UsernameField(
        widget=forms.TextInput(
            attrs={
                "class": "input-control",
                "placeholder": "Username",
                "autocomplete": "username",
            }
        )
    )
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "input-control",
                "placeholder": "Password",
                "autocomplete": "current-password",
            }
        ),
    )


class RegisterForm(UserCreationForm):
    """User registration with email support and styled widgets."""

    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(
            attrs={
                "class": "input-control",
                "placeholder": "Email address",
                "autocomplete": "email",
            }
        ),
    )

    password1 = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "input-control",
                "placeholder": "Password",
                "autocomplete": "new-password",
            }
        ),
    )

    password2 = forms.CharField(
        label="Confirm password",
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "input-control",
                "placeholder": "Confirm password",
                "autocomplete": "new-password",
            }
        ),
    )

    class Meta(UserCreationForm.Meta):
        fields = ("username", "email")
        widgets = {
            "username": forms.TextInput(
                attrs={
                    "class": "input-control",
                    "placeholder": "Username",
                    "autocomplete": "username",
                }
            ),
        }

    def save(self, commit: bool = True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user
