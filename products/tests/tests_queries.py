from django.test import TestCase
from unittest.mock import patch

from products.models import ProdBrand, ProdCat, ProdStore, Products, UserSave, Brands, Stores, Categories
from user.models import User

from products.queries import GetProductsQueryTool, CheckProduct, UserProducts


class GetProductsQueryToolTest(TestCase):

    fixtures = ['products.json']

    def setUp(self):
        self.code = '3017620422003'

    def test_get_products_by_brand(self):

        products = GetProductsQueryTool('Brand').get_products_by_brand()

        self.assertNotEqual(products.count(), 0)

        self.assertQuerysetEqual(
            products,
            Products.objects.filter(code=self.code),
            transform=lambda x: x
        )

    def test_get_products_by_category_by_name_fr(self):

        products = GetProductsQueryTool('Aide culinaire sucrée').get_products_by_category()

        self.assertNotEqual(products.count(), 0)

        self.assertQuerysetEqual(
            products,
            Products.objects.filter(code=self.code),
            transform=lambda x: x
        )

    def test_get_products_by_category_by_name(self):

        products = GetProductsQueryTool('en:sugary-cooking-helpers').get_products_by_category()

        self.assertNotEqual(products.count(), 0)

        self.assertQuerysetEqual(
            products,
            Products.objects.filter(code=self.code),
            transform=lambda x: x
        )

    def test_get_products_by_store(self):

        products = GetProductsQueryTool('Store').get_products_by_store()

        self.assertNotEqual(products.count(), 0)

        self.assertQuerysetEqual(
            products,
            Products.objects.filter(code=self.code),
            transform=lambda x: x
        )

    def test_get_all_products(self):

        products = GetProductsQueryTool('nutella').get_all_products()

        self.assertNotEqual(products.count(), 0)

        self.assertQuerysetEqual(
            products,
            Products.objects.filter(code=self.code),
            transform=lambda x: x
        )

class CheckProductTest(TestCase):

    fixtures = ['products.json']

    def setUp(self):
        self.code = '3017620422003'
        self.check_product = CheckProduct(self.code)
    
    def test_init_checkproduct(self):

        self.assertEqual(
            self.check_product.code,
            self.code
        )

    def test_check_product_exists(self):

        product = self.check_product.check()

        self.assertEqual(
            product,
            Products.objects.get(code=self.code)
        )

    def test_check_product_not_exists(self):

        invalid_code = 'invalid_code'

        new_check_product = CheckProduct(invalid_code)

        self.assertEqual(
            new_check_product.code,
            invalid_code
        )
        self.assertIsNone(new_check_product.check())

    def test_check_brands(self):

        brand, brands = self.check_product.get_brands()

        list_brands = list(Brands.objects.all().values_list('name', flat=True))

        self.assertIn(
            brand,
            list_brands
        )
        self.assertTrue(
            set(brands).issubset(set(list_brands))
        )

    def test_check_stores(self):

        stores = self.check_product.get_stores()

        list_stores = list(Stores.objects.all().values_list('name', flat=True))

        self.assertTrue(
            set(stores).issubset(set(list_stores))
        )

    def test_check_categories(self):

        categories = self.check_product.get_categories()


        categories_objects = Categories.objects.all()
        dict_categories = dict()
        for category in categories_objects:
            dict_categories[category.name] = category.name_fr

        self.assertIsInstance(
            categories,
            dict
        )
        self.assertNotEqual(categories, {})
        self.assertTrue(
            set(categories.keys()).issubset(dict_categories.keys()),
        )
        for key in categories.keys():
            self.assertEqual(
                categories[key],
                dict_categories[key]
            )

    def test_check_alternatives(self):

        # nutriscore == D
        product = Products.objects.get(
            code=self.code
        )
        # nutriscore == C
        alternative = Products.objects.get(
            code="11111111111"
        )
        # nutriscore == E
        not_alternative = Products.objects.get(
            code="22222222222"
        )

        alternatives = self.check_product.get_alternatives()

        self.assertIn(
            alternative,
            alternatives
        )
        self.assertNotIn(
            product,
            alternatives
        )
        self.assertNotIn(
            not_alternative,
            alternatives
        )


class CheckUsersaveTest(TestCase):

    fixtures = ['users.json', 'products.json', 'usersave.json']

    def setUp(self):
        self.code = '3017620422003'
        self.user = User.objects.get(username='admin')
        self.user_product = UserProducts(self.user)
    
    def test_init_usersave(self):

        self.assertEqual(
            self.user,
            self.user_product.user
        )

    def test_check_user_products(self):

        products = self.user_product.get_user_products()

        self.assertQuerysetEqual(
            products,
            Products.objects.filter(code=self.code),
            transform=lambda x: x
        )
