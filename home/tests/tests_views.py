"""Test home views"""
from django.test import TestCase


class HomeViewTests(TestCase):
    """Testing home view"""

    def test_home_view(self):
        """Test get user home"""

        self.client.get('/')

        self.assertTemplateUsed('home.html')

    def test_legals(self):
        """Test legals page"""

        self.client.get('/legal_notice/')

        self.assertTemplateUsed('legal_notice.html')
