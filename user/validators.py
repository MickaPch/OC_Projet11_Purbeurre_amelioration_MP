"""User validators"""
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class UsernameValidator(RegexValidator):
    """Validate username"""
    regex = r'^[^_\W]+\Z'
    message = _(
        'Enter a valid username. This value may contain only letters '
        '([A-Z] & [a-z]) and numbers ([0-9]).'
    )
    flags = 0
    code = 'invalid_username'

validate_username = UsernameValidator()

class CapitalValidator:
    """Password validator check if includes at least one capital"""

    def validate(self, password, user=None):
        """check password contains one capital"""
        capital = False
        for caracter in password:
            if caracter.isupper():
                capital = True
                break

        if not capital:
            msg_error = 'This password must contain at least one capital.'
            raise ValidationError(
                _(msg_error),
                code='password_missing_capital'
            )

    def get_help_text(self):
        """Return help text"""
        return "Your password must contain at least one capital"

class DigitValidator:
    """Password validator check if includes at least one digit"""

    def validate(self, password, user=None):
        """check password contains one digit"""
        digit = False
        for caracter in password:
            if caracter.isdigit():
                digit = True
                break

        if not digit:
            msg_error = 'This password must contain at least one digit.'
            raise ValidationError(
                _(msg_error),
                code='password_missing_digit'
            )

    def get_help_text(self):
        """Return help text"""
        return "Your password must contain at least one digit"

class SpecialCharacterValidator:
    """Password validator check if includes at least one special caracter"""

    special_caracters = list('!#$%&*+,-.:;=?@_')

    def validate(self, password, user=None):
        """Check password contains one special caracter"""
        special = False
        for caracter in password:
            if caracter in self.special_caracters:
                special = True
                break

        if not special:
            msg_error = 'This password must contain at least one special caracter.'
            raise ValidationError(
                _(msg_error),
                code='password_missing_special'
            )

    def get_help_text(self):
        """Return help text"""
        return "Your password must contain at least one special caracter"
