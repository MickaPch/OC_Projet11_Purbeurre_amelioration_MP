"""Tests products app"""
from django.apps import apps
from django.test import TestCase

from products.apps import ProductsConfig


class ProductsConfigTest(TestCase):
    """Testing products app"""

    def test_app_products(self):
        """Test app name"""
        self.assertEqual(
            ProductsConfig.name,
            'products'
        )
        self.assertEqual(
            apps.get_app_config('products').name,
            'products'
        )
