"""Module user.models"""
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.mail import send_mail
from django.db import models
from django.utils.translation import gettext_lazy as _

from smtplib import SMTPException

from .validators import UsernameValidator


class UserManager(BaseUserManager):
    """
    Define a model manager for User model
    with username field facultative
    and email required
    """

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """Create and save a User with the given email and password."""
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        # Send email
        # try:
        if user.first_name != '':
            username = user.first_name
        else:
            username = user.username
        mail_body = f'Bonjour {username} et bienvenue sur la plateforme de comparaison de produits Pur Beurre !'
        send_mail(
            'Bienvenue !',
            mail_body,
            None,
            [email],
            fail_silently=False,
        )
        # except SMTPException as error:
        #     print(error)
        # except:
        #     print('send mail FAILED')

        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular User with the given email and password."""

        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        extra_fields.setdefault('is_active', True) # Change to False if verification by mail

        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        """Create and save a SuperUser with the given email and password."""

        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('SuperUser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('SuperUser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)

class User(AbstractUser):
    """User model for Pur Beurre"""

    # Change Username validator
    username_validator = UsernameValidator()

    username = models.CharField(
        _('username'),
        max_length=150,
        unique=True,
        help_text=_('Required. 150 characters or fewer. Letters and digits only.'),
        validators=[username_validator],
        error_messages={
            'unique': _("A user with that username already exists."),
        },
    )
    # Unique = True for email address
    email = models.EmailField(
        _('email address'),
        unique=True
    )

    # Email at username field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    # def email_user(self, *args, **kwargs):
    #     send_mail(
    #         '{}'.format(args[0]),
    #         '{}'.format(args[1]),
    #         '{}'.format(args[2]),
    #         [self.email],
    #         fail_silently=False,
    #     )

class Newsletter(models.Model):
    """OneToOne Field for mail newsletter"""

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    newsletter = models.BooleanField(default=False)
