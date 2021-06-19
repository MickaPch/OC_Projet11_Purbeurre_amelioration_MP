"""Create JSON fixture products saved for user"""
import os
import json

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    """
    Command to create fixture for products saved by user
    for tests
    """

    def handle(self, *args, **kwargs):
        """command user products fixture"""

        products = [
            {
                "model": "products.UserSave",
                "pk": 1,
                "fields": {
                    "user": 1,
                    "product": "3017620422003",
                    "date": "2020-12-31"
                }
            }
        ]
        path_file = os.path.join(
            os.path.dirname(
                os.path.dirname(
                    os.path.dirname(__file__)
                )
            ),
            'fixtures',
            'usersave.json'
        )

        with open(path_file, 'w') as file_fixture:
            file_fixture.write(json.dumps(products))
