"""Products models"""
from django.db import models


class Products(models.Model):
    """Products retrieved from OpenFoodFacts"""

    code = models.CharField(max_length=250, primary_key=True, null=False)
    name = models.CharField(max_length=250, null=False)
    url = models.TextField(null=True)
    quantity = models.CharField(max_length=250, null=True)
    country = models.CharField(max_length=250, null=False)
    ingredients = models.TextField(null=True)
    energy = models.IntegerField(null=True)
    fat = models.IntegerField(null=True)
    satured_fat = models.IntegerField(null=True)
    carbohydrates = models.IntegerField(null=True)
    sugar = models.IntegerField(null=True)
    fibers = models.IntegerField(null=True)
    proteins = models.IntegerField(null=True)
    salt = models.IntegerField(null=True)
    sodium = models.IntegerField(null=True)
    nutriscore = models.CharField(max_length=1, null=True)
    image_url = models.TextField(null=True)
    compare_to_category = models.ForeignKey('Categories', on_delete=models.CASCADE, null=False)

class Stores(models.Model):
    """List of stores"""

    name = models.CharField(max_length=250, null=False)

class Categories(models.Model):
    """List of categories and its parents/children"""

    name = models.CharField(max_length=250, null=False, primary_key=True)
    name_fr = models.CharField(max_length=250, null=False)
    url = models.CharField(max_length=250, null=False)

class RelatedCategories(models.Model):
    """Related categories"""
    parent = models.ForeignKey(
        'Categories',
        on_delete=models.CASCADE,
        null=False,
        related_name="parent"
    )
    child = models.ForeignKey(
        'Categories',
        on_delete=models.CASCADE,
        null=False,
        related_name="child"
    )

class UserSave(models.Model):
    """Products saved by user"""

    user = models.ForeignKey('user.User', on_delete=models.CASCADE, null=False)
    product = models.ForeignKey(
        'Products',
        on_delete=models.CASCADE,
        null=False
    )
    date = models.DateField(auto_now=True)

class Brands(models.Model):
    """Brands"""

    name = models.CharField(max_length=250, null=True)

class ProdCat(models.Model):
    """Connections between products and its categories"""

    product = models.ForeignKey('Products', on_delete=models.CASCADE, null=False)
    category = models.ForeignKey('Categories', on_delete=models.CASCADE, null=False)

class ProdStore(models.Model):
    """Connections between products and stores where find them"""

    product = models.ForeignKey('Products', on_delete=models.CASCADE, null=False)
    store = models.ForeignKey('Stores', on_delete=models.CASCADE, null=False)

class ProdBrand(models.Model):
    """Connections between products and brands"""

    product = models.ForeignKey('Products', on_delete=models.CASCADE, null=False)
    brand = models.ForeignKey('Brands', on_delete=models.CASCADE, null=False)
