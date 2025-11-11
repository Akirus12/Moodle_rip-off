"""
Forms for file operations and sharing.
"""
from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from core.models import File, FileShare, PermissionLevel


class FileUploadForm(forms.Form):
    """Form for uploading files."""

    name = forms.CharField(
        max_length=255,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'input-control',
            'placeholder': 'Enter file name',
        })
    )

    description = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'input-control',
            'placeholder': 'Optional description',
            'rows': 3,
        })
    )

    file = forms.FileField(
        required=True,
        widget=forms.FileInput(attrs={
            'class': 'input-control',
        })
    )

    def clean_name(self):
        """Validate and clean the name field."""
        name = self.cleaned_data.get('name', '').strip()
        if not name:
            raise ValidationError("File name is required")
        if len(name) < 3:
            raise ValidationError("File name must be at least 3 characters")
        return name

    def clean_description(self):
        """Clean the description field."""
        description = self.cleaned_data.get('description', '').strip()
        if len(description) > 2000:
            raise ValidationError("Description is too long (max 2000 characters)")
        return description


class FileShareCreateForm(forms.ModelForm):
    """Form for creating file share links."""

    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'input-control',
            'placeholder': 'Optional password protection',
        }),
        help_text="Leave blank for no password protection"
    )

    password_confirm = forms.CharField(
        required=False,
        label="Confirm password",
        widget=forms.PasswordInput(attrs={
            'class': 'input-control',
            'placeholder': 'Confirm password',
        })
    )

    expiration_days = forms.IntegerField(
        required=False,
        min_value=1,
        max_value=365,
        initial=30,
        widget=forms.NumberInput(attrs={
            'class': 'input-control',
            'placeholder': 'Days until expiration (optional)',
        }),
        help_text="Leave blank for no expiration"
    )

    class Meta:
        model = FileShare
        fields = [
            'view_permission_level',
            'edit_permission_level',
            'download_permission_level',
        ]
        widgets = {
            'view_permission_level': forms.Select(attrs={'class': 'input-control'}),
            'edit_permission_level': forms.Select(attrs={'class': 'input-control'}),
            'download_permission_level': forms.Select(attrs={'class': 'input-control'}),
        }
        help_texts = {
            'view_permission_level': 'Who can view file metadata',
            'edit_permission_level': 'Who can edit file metadata',
            'download_permission_level': 'Who can download the file',
        }

    def clean(self):
        """Validate password confirmation."""
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')

        if password and password != password_confirm:
            raise ValidationError("Passwords do not match")

        if password and len(password) < 6:
            raise ValidationError("Password must be at least 6 characters")

        return cleaned_data

    def save(self, commit=True):
        """Save with password hashing if provided."""
        instance = super().save(commit=False)

        password = self.cleaned_data.get('password')
        if password:
            from django.contrib.auth.hashers import make_password
            import secrets

            instance.is_password_protected = True
            instance.password_salt = secrets.token_hex(16)
            instance.hashed_password = make_password(
                password + instance.password_salt
            )
        else:
            instance.is_password_protected = False
            instance.hashed_password = None
            instance.password_salt = None

        # Set expiration date
        expiration_days = self.cleaned_data.get('expiration_days')
        if expiration_days:
            instance.expiration_date = timezone.now() + timedelta(days=expiration_days)
        else:
            instance.expiration_date = None

        if commit:
            instance.save()

        return instance


class SharePasswordForm(forms.Form):
    """Form for entering password to access protected share."""

    password = forms.CharField(
        required=True,
        widget=forms.PasswordInput(attrs={
            'class': 'input-control',
            'placeholder': 'Enter password',
        })
    )


class FileDeleteForm(forms.Form):
    """Form for confirming file deletion."""

    confirm = forms.BooleanField(
        required=True,
        label="I confirm I want to delete this file",
        widget=forms.CheckboxInput(attrs={
            'class': 'checkbox-control',
        })
    )


class FileEditForm(forms.ModelForm):
    """Form for editing file metadata."""

    class Meta:
        model = File
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'input-control',
                'placeholder': 'File name',
            }),
            'description': forms.Textarea(attrs={
                'class': 'input-control',
                'placeholder': 'File description',
                'rows': 3,
            }),
        }

    def clean_name(self):
        """Validate and clean the name field."""
        name = self.cleaned_data.get('name', '').strip()
        if not name:
            raise ValidationError("File name is required")
        if len(name) < 3:
            raise ValidationError("File name must be at least 3 characters")
        return name
