"""Module user.forms"""
from django import forms
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.utils.safestring import mark_safe


class ConnectionForm(forms.Form):
    """Connection form"""
    prefix = "connect"
    user_login = forms.CharField(label="Email ou login")
    pwd = forms.CharField(label="Mot de passe", widget=forms.PasswordInput)

    user_login.widget.attrs.update(
        {
            'class': 'form-control',
            'placeholder': 'Email ou login'
        }
    )
    pwd.widget.attrs.update(
        {
            'class': 'form-control',
            'placeholder': 'Mot de passe'
        }
    )

class NewForm(forms.Form):
    """New account form"""

    username_validator = UnicodeUsernameValidator()

    email = forms.EmailField(label="Email *")
    user_login = forms.CharField(
        max_length=150,
        validators=[username_validator],
        required=False
    )
    pwd = forms.CharField(
        label="Mot de passe *",
        widget=forms.PasswordInput
    )
    pwd_confirm = forms.CharField(
        label="Confirmation du mot de passe",
        widget=forms.PasswordInput
    )
    firstname = forms.CharField(
        label="Prénom",
        max_length=30,
        required=False,
    )
    lastname = forms.CharField(
        label="Nom",
        max_length=30,
        required=False,
    )
    string_cgu = "J'ai lu et j'accepte les <a href='#' target='_blank'>" \
                 "Conditions Générales d'Utilisation</a>."
    cgu = forms.BooleanField(
        label=mark_safe(string_cgu),
        required=True
    )
    newsletter = forms.BooleanField(
        label="Newsletter",
        required=False
    )

    email.widget.attrs.update(
        {
            'class': 'form-control is-invalid has-popover',
            'placeholder': 'Email',
            'data-content': """
            <div class="invalid-input">
                Veuillez entrer votre adresse mail.
            </div>
            """,
            'data-html': "true",
            'data-placement': "left",
            'data-container': "body"
        }
    )
    user_login.widget.attrs.update(
        {
            'class': 'form-control has-popover',
            'placeholder': 'Login',
            'data-content': """
            <div>
                Facultatif. Peut être utilisé comme identifiant de connexion.
            </div>
            """,
            'data-html': "true",
            'data-placement': "left",
            'data-container': "body"
        }
    )
    pwd.widget.attrs.update(
        {
            'class': 'form-control is-invalid has-popover',
            'placeholder': 'Mot de passe',
            'data-content': """
                <div class="invalid-input">Au moins 8 charactères</div>
                <div class="invalid-input">Au moins 1 lettre majuscule</div>
                <div class="invalid-input">Au moins 1 chiffre</div>
                <div class="invalid-input">Au moins 1 charactère spécial</div>
            """,
            'data-html': "true",
            'data-placement': "left",
            'data-container': "body"
        }
    )
    pwd_confirm.widget.attrs.update(
        {
            'class': 'form-control is-invalid',
            'placeholder': 'Veuillez retaper le mot de passe',
            'data-content': """
                <div class="invalid-input">Les mots de passe ne correspondent pas.</div>
            """,
            'data-html': "true",
            'data-placement': "left",
            'data-container': "body"
        }
    )
    firstname.widget.attrs.update(
        {
            'class': 'form-control',
            'placeholder': 'Prénom'
        }
    )
    lastname.widget.attrs.update(
        {
            'class': 'form-control',
            'placeholder': 'Nom'
        }
    )
    cgu.widget.attrs.update(
        {
            'class': 'form-check-input is-invalid'
        }
    )
    newsletter.widget.attrs.update(
        {
            'class': 'form-check-input'
        }
    )

    def clean(self):
        cleaned_data = super().clean()
        pwd = cleaned_data.get("pwd")
        pwd_confirm = cleaned_data.get("pwd_confirm")

        if pwd != pwd_confirm:
            raise forms.ValidationError(
                "password and confirm_password does not match"
            )
