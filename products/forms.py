"""Homepage forms"""
from django import forms

from products.models import (
    Products,
    UserSave
)


class SearchForm(forms.Form):
    """Product search form"""
    product_search = forms.CharField(
        max_length=100
    )

    product_search.widget.attrs.update(
        {
            'class': 'form-control input-search-product',
            'placeholder': 'Chercher un produit'
        }
    )

class SaveForm(forms.Form):
    """Save form"""

    products_to_save = forms.TextInput()

    def save_products(self, user):
        """Save products if valid form"""

        new_products = self.data.get('products_to_save').split(',')
        for product_code in new_products:
            product_object = Products.objects.get(
                code=product_code
            )
            product, new_product = UserSave.objects.get_or_create(
                user=user,
                product=product_object
            )
            if not new_product:
                product.save()

class DeleteForm(forms.Form):
    """Delete form"""

    products_to_delete = forms.TextInput()

    def delete_products(self, user):
        """Delete products if valid form"""

        products = self.data.get('products_to_delete').split(',')
        for product_code in products:
            product_object = Products.objects.get(
                code=product_code
            )
            UserSave.objects.filter(
                user=user,
                product=product_object
            ).delete()
