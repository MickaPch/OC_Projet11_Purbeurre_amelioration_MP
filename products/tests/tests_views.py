"""Tests products views"""
from django.test import TestCase
from unittest.mock import patch

from products.views import ProductFormContext
from products.models import Products

class ProductFormTest(TestCase):
    """Testing product form view"""

    def setUp(self):
        self.product_form = {'product_search': 'some_product'}

    @patch('products.views.SearchForm')
    def test_search_form(self, MockSearchForm):
        attrs = {
            'return_value.is_valid.return_value': True,
            'return_value.cleaned_data': self.product_form
        }
        MockSearchForm.configure_mock(**attrs)
        context_object = ProductFormContext()
        response = context_object.get_context_data()
        MockSearchForm.assert_called()
        self.assertIn(
            'search_form',
            response
        )

class ProductFormRedirectTest(TestCase):
    """Testing products form redirect to views"""

    def setUp(self):
        self.product = 'some_product'

    @patch('products.views.CheckProduct')
    @patch('products.views.SearchForm')
    def test_search_product_form_success(self, MockSearchForm, MockCheckProduct):
        product_form = {'product_search': self.product}
        attrs = {
            'return_value.is_valid.return_value': True,
            'return_value.cleaned_data': product_form
        }
        MockSearchForm.configure_mock(**attrs)
        MockCheckProduct.return_value.product = None
        response = self.client.post(
            '/products/search',
            product_form
        )
        MockSearchForm.assert_called()
        self.assertRedirects(
            response,
            f'/products/search/{self.product}/',
            fetch_redirect_response=False
        )

    @patch('products.views.CheckProduct')
    @patch('products.views.SearchForm')
    def test_search_product_form_redirect_homepage(self, MockSearchForm, MockCheckProduct):
        product_form = {'product_search': self.product}
        attrs = {
            'return_value.is_valid.return_value': False,
            'return_value.cleaned_data': product_form
        }
        MockSearchForm.configure_mock(**attrs)
        MockCheckProduct.return_value.product = None
        response = self.client.post(
            '/products/search',
            product_form
        )
        MockSearchForm.assert_called()
        self.assertRedirects(
            response,
            '/',
            fetch_redirect_response=False
        )

    @patch('products.views.CheckProduct')
    @patch('products.views.SearchForm')
    def test_search_product_form_redirect_product(self, MockSearchForm, MockCheckProduct):
        product_form = {'product_search': self.product}
        attrs = {
            'return_value.is_valid.return_value': True,
            'return_value.cleaned_data': product_form
        }
        MockSearchForm.configure_mock(**attrs)
        MockCheckProduct.return_value.product = object()
        response = self.client.post(
            '/products/search',
            product_form
        )
        MockSearchForm.assert_called()
        self.assertRedirects(
            response,
            f'/products/product/{self.product}/',
            fetch_redirect_response=False
        )


class ProductsViewTest(TestCase):
    """Testing products view"""

    def setUp(self):
        self.product = 'some_product'

    @patch('products.views.GetProductsQueryTool')
    @patch('products.views.SearchForm')
    def test_search_products_good_template(self, MockSearchForm, MockGetProductsQueryTool):
        MockSearchForm.return_value.is_valid.return_value = True
        MockSearchForm.return_value.cleaned_data = {
            'product_search': self.product
        }
        MockGetProductsQueryTool.return_value.get_all_products.return_value = Products.objects.all()
        self.client.get(f'/products/search/{self.product}')

        self.assertTemplateUsed('products/search.html')
        
    @patch('products.views.GetProductsQueryTool')
    @patch('products.views.SearchForm')
    def test_search_products_good_context(self, MockSearchForm, MockGetProductsQueryTool):
        MockSearchForm.return_value.is_valid.return_value = True
        MockSearchForm.return_value.cleaned_data = {
            'product_search': self.product
        }
        MockGetProductsQueryTool.return_value.get_all_products.return_value = Products.objects.all()
        response = self.client.get(f'/products/search/{self.product}/')
        MockGetProductsQueryTool.assert_called_with(self.product)
        self.assertIn(
            'search_type',
            response.context
        )
        self.assertEqual(
            'search',
            response.context['search_type']
        )


class BrandViewTest(TestCase):
    """Testing brand view"""

    def setUp(self):
        self.brand = 'some_brand'

    @patch('products.views.GetProductsQueryTool')
    @patch('products.views.SearchForm')
    def test_search_products_good_template(self, MockSearchForm, MockGetProductsQueryTool):
        MockSearchForm.return_value.is_valid.return_value = True
        MockSearchForm.return_value.cleaned_data = {
            'product_search': self.brand
        }
        MockGetProductsQueryTool.return_value.get_products_by_brand.return_value = Products.objects.all()
        self.client.get(f'/products/brand/{self.brand}')

        self.assertTemplateUsed('products/search.html')

    @patch('products.views.GetProductsQueryTool')
    @patch('products.views.SearchForm')
    def test_search_products_good_context(self, MockSearchForm, MockGetProductsQueryTool):
        MockSearchForm.return_value.is_valid.return_value = True
        MockSearchForm.return_value.cleaned_data = {
            'product_search': self.brand
        }
        MockGetProductsQueryTool.return_value.get_products_by_brand.return_value = Products.objects.all()
        response = self.client.get(f'/products/brand/{self.brand}/')
        MockGetProductsQueryTool.assert_called_with(self.brand)
        self.assertIn(
            'search_type',
            response.context
        )
        self.assertEqual(
            'brand',
            response.context['search_type']
        )


class CategoryViewTest(TestCase):
    """Testing category view"""

    def setUp(self):
        self.category = 'some_category'

    @patch('products.views.GetProductsQueryTool')
    @patch('products.views.SearchForm')
    def test_search_products_good_template(self, MockSearchForm, MockGetProductsQueryTool):
        MockSearchForm.return_value.is_valid.return_value = True
        MockSearchForm.return_value.cleaned_data = {
            'product_search': self.category
        }
        MockGetProductsQueryTool.return_value.get_products_by_category.return_value = Products.objects.all()
        self.client.get(f'/products/category/{self.category}')

        self.assertTemplateUsed('products/search.html')

    @patch('products.views.GetProductsQueryTool')
    @patch('products.views.SearchForm')
    def test_search_products_good_context(self, MockSearchForm, MockGetProductsQueryTool):
        MockSearchForm.return_value.is_valid.return_value = True
        MockSearchForm.return_value.cleaned_data = {
            'product_search': self.category
        }
        MockGetProductsQueryTool.return_value.get_products_by_category.return_value = Products.objects.all()
        response = self.client.get(f'/products/category/{self.category}/')
        MockGetProductsQueryTool.assert_called_with(self.category)
        self.assertIn(
            'search_type',
            response.context
        )
        self.assertEqual(
            'category',
            response.context['search_type']
        )


class StoreViewTest(TestCase):
    """Testing store view"""

    def setUp(self):
        self.store = 'some_store'

    @patch('products.views.GetProductsQueryTool')
    @patch('products.views.SearchForm')
    def test_search_products_good_template(self, MockSearchForm, MockGetProductsQueryTool):
        MockSearchForm.return_value.is_valid.return_value = True
        MockSearchForm.return_value.cleaned_data = {
            'product_search': self.store
        }
        MockGetProductsQueryTool.return_value.get_products_by_store.return_value = Products.objects.all()
        self.client.get(f'/products/store/{self.store}')

        self.assertTemplateUsed('products/search.html')

    @patch('products.views.GetProductsQueryTool')
    @patch('products.views.SearchForm')
    def test_search_products_good_context(self, MockSearchForm, MockGetProductsQueryTool):
        MockSearchForm.return_value.is_valid.return_value = True
        MockSearchForm.return_value.cleaned_data = {
            'product_search': self.store
        }
        MockGetProductsQueryTool.return_value.get_products_by_store.return_value = Products.objects.all()
        response = self.client.get(f'/products/store/{self.store}/')
        MockGetProductsQueryTool.assert_called_once_with(self.store)
        self.assertIn(
            'search_type',
            response.context
        )
        self.assertEqual(
            'store',
            response.context['search_type']
        )


class ProductViewTest(TestCase):
    """Testing product view"""

    fixtures = ['users.json']

    def setUp(self):
        self.code = 'some_product'
        self.user = {
            'username': 'foo@example.com',
            'password': 'admin'
        }
        self.attrs = {
            'return_value.product': object(),
            'return_value.get_brands.return_value': [Products.objects.first(), Products.objects.all()],
            'return_value.get_stores.return_value': Products.objects.all(),
            'return_value.get_categories.return_value': dict(),
            'return_value.get_alternatives.return_value': Products.objects.all(),
        }

    @patch('products.views.CheckProduct')
    def test_search_product_good_template(self, MockCheckProduct):
        MockCheckProduct.configure_mock(**self.attrs)
        self.client.get(f'/products/product/{self.code}/')

        self.assertTemplateUsed('products/product.html')

    @patch('products.views.CheckProduct')
    def test_search_product_good_context(self, MockCheckProduct):
        MockCheckProduct.configure_mock(**self.attrs)
        response = self.client.get(f'/products/product/{self.code}/')
        self.assertIn(
            'product',
            response.context
        )
        self.assertNotIn(
            'user_products',
            response.context
        )
        self.assertIsInstance(
            response.context['product'],
            object
        )

    @patch('products.views.UserProducts')
    @patch('products.views.CheckProduct')
    def test_search_product_good_context_user_connected(self, MockCheckProduct, MockUserProducts):
        MockCheckProduct.configure_mock(**self.attrs)
        MockUserProducts.return_value.get_user_products.return_value = Products.objects.all()
        self.client.login(**self.user)
        response = self.client.get(f'/products/product/{self.code}/')
        self.assertIn(
            'product',
            response.context
        )
        self.assertIn(
            'user_products',
            response.context
        )
        self.assertIsInstance(
            response.context['product'],
            object
        )


class UserProductsTest(TestCase):
    """Testing user product view"""

    fixtures = ['users.json']

    def setUp(self):
        self.user = {
            'username': 'foo@example.com',
            'password': 'admin'
        }
        self.attrs = {
            'return_value.get_user_products.return_value': Products.objects.all(),
        }

    def test_search_user_products_user_not_connected(self):
        response = self.client.get(f'/products/my_products/')

        self.assertNotEqual(response.status_code, 200)

    @patch('products.views.UserProducts')
    def test_search_user_products_user_connected(self, MockUserProducts):
        MockUserProducts.configure_mock(**self.attrs)

        self.client.login(**self.user)
        response = self.client.get(f'/products/my_products/')

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed('products/my_products.html')

    @patch('products.views.UserProducts')
    def test_search_user_products_check_context(self, MockUserProducts):
        MockUserProducts.configure_mock(**self.attrs)

        self.client.login(**self.user)
        response = self.client.get(f'/products/my_products/')

        self.assertIn(
            'products',
            response.context
        )
        self.assertQuerysetEqual(
            response.context['products'],
            Products.objects.all(),
            transform=lambda x: x
        )

class SaveViewTest(TestCase):
    """Test save view"""

    fixtures = ['users.json']

    def setUp(self):
        self.user = {
            'username': 'foo@example.com',
            'password': 'admin'
        }
        self.form = {'products_to_save': 'some_products'}

    @patch('products.views.SaveView.form_class')
    def test_save_products_user_not_connected(self, MockSaveForm):
        MockSaveForm.return_value.is_valid.return_value = True
        response = self.client.post(
            '/products/save',
            self.form
        )
        self.assertNotEqual(response.status_code, 200)

    @patch('products.views.SaveView.form_class')
    def test_save_products_user_connected(self, MockSaveForm):
        MockSaveForm.return_value.is_valid.return_value = True
        MockSaveForm.return_value.save_products.return_value = True
        self.client.login(**self.user)
        response = self.client.post(
            '/products/save',
            self.form
        )
        self.assertRedirects(
            response,
            '/products/my_products/',
            fetch_redirect_response=False
        )


class DeleteViewTest(TestCase):
    """Test delete view"""

    fixtures = ['users.json']

    def setUp(self):
        self.user = {
            'username': 'foo@example.com',
            'password': 'admin'
        }
        self.form = {'products_to_delete': 'some_products'}

    @patch('products.views.DeleteView.form_class')
    def test_delete_products_user_not_connected(self, MockDeleteForm):
        MockDeleteForm.return_value.is_valid.return_value = True
        response = self.client.post(
            '/products/delete',
            self.form
        )
        self.assertNotEqual(response.status_code, 200)

    @patch('products.views.DeleteView.form_class')
    def test_delete_products_user_connected(self, MockDeleteForm):
        MockDeleteForm.return_value.is_valid.return_value = True
        MockDeleteForm.return_value.save_products.return_value = True
        self.client.login(**self.user)
        response = self.client.post(
            '/products/delete',
            self.form
        )
        self.assertRedirects(
            response,
            '/products/my_products/',
            fetch_redirect_response=False
        )

