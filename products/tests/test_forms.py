from django.test import TestCase

from products.forms import SaveForm, DeleteForm

from products.models import Products, UserSave
from user.models import User


class SaveFormTest(TestCase):

    fixtures = ['users.json', 'products.json']

    def setUp(self):
        self.user = User.objects.get(username='admin')
        self.code = '3017620422003'
        self.product = Products.objects.get(
            code=self.code
        )
        self.save_form = SaveForm(
            data={'products_to_save': self.code}
        )

    def test_save_product(self):

        user_products = UserSave.objects.filter(
            user=self.user
        )
        products = Products.objects.filter(
            usersave__in=user_products
        )
        self.assertNotIn(
            self.product,
            products
        )

        self.save_form.save_products(self.user)

        user_products = UserSave.objects.filter(
            user=self.user
        )
        products = Products.objects.filter(
            usersave__in=user_products
        )
        self.assertIn(
            self.product,
            products
        )

    def test_actualize_product(self):

        self.save_form.save_products(self.user)

        user_products = UserSave.objects.filter(
            user=self.user
        )
        products = Products.objects.filter(
            usersave__in=user_products
        )
        self.assertIn(
            self.product,
            products
        )
        self.assertEqual(products.count(), 1)

        self.save_form.save_products(self.user)

        user_products = UserSave.objects.filter(
            user=self.user
        )
        products = Products.objects.filter(
            usersave__in=user_products
        )
        self.assertIn(
            self.product,
            products
        )
        self.assertEqual(products.count(), 1)

class DeleteFormTest(TestCase):

    fixtures = ['users.json', 'products.json', 'usersave.json']

    def setUp(self):
        self.user = User.objects.get(username='admin')
        self.code = '3017620422003'
        self.product = Products.objects.get(
            code=self.code
        )
        self.delete_form = DeleteForm(
            data={'products_to_delete': self.code}
        )
        self.usersave = Products.objects.filter(
            usersave__in=UserSave.objects.filter(
                user=self.user
            )
        )

    def test_delete_product(self):

        self.assertIn(
            self.product,
            self.usersave
        )
        self.assertEqual(self.usersave.count(), 1)

        self.delete_form.delete_products(self.user)

        user_products = UserSave.objects.filter(
            user=self.user
        )
        usersave_after_delete = Products.objects.filter(
            usersave__in=user_products
        )
        self.assertNotIn(
            self.product,
            usersave_after_delete
        )
        self.assertEqual(self.usersave.count(), 1)
