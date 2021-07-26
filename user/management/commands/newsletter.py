
from django.core.mail import send_mail
from django.core.management.base import BaseCommand
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from user.models import Newsletter


class Command(BaseCommand):
    """command to make an admin user"""

    def handle(self, *args, **kwargs):
        """command to make an admin user"""

        all_users_newsletter = Newsletter.objects.filter(newsletter=True)

        newsletter_mail_object = 'NEWSLETTER'
        
        html_message = render_to_string('newsletter/index.html', {'context': 'values'})
        newsletter_mail_body = strip_tags(html_message)

        for newsletter_user in all_users_newsletter:
            email = newsletter_user.user.email
            send_mail(
                newsletter_mail_object,
                newsletter_mail_body,
                None,
                [email],
                fail_silently=False,
            )
