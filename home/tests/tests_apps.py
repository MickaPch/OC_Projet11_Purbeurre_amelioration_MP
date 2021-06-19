"""Test home app"""
from django.apps import apps
from django.test import TestCase

from home.apps import HomeConfig


class HomeConfigTest(TestCase):
    """Testing home app"""

    def test_app_(self):
        """Test app name"""
        self.assertEqual(
            HomeConfig.name,
            'home'
        )
        self.assertEqual(
            apps.get_app_config('home').name,
            'home'
        )
