"""Products database queries"""
from django.db.models import Q
from products.models import ProdBrand, ProdCat, ProdStore, Products, UserSave


class GetProductsQueryTool():
    """Return products queryset"""

    def __init__(self, search):
        self.search = search

    def get_products_by_brand(self):
        """Return products found by brand"""
        prodbrand_results = ProdBrand.objects.filter(
            brand__name__icontains=self.search
        )
        products = Products.objects.filter(
            prodbrand__in=prodbrand_results
        ).distinct()

        return products

    def get_products_by_category(self):
        """Return products found by category"""
        prodcat_results = ProdCat.objects.filter(
            Q(category__name__icontains=self.search)
            | Q(category__name_fr__icontains=self.search)
        )
        products = Products.objects.filter(
            prodcat__in=prodcat_results
        ).distinct()

        return products

    def get_products_by_store(self):
        """Return products found by store"""
        prodstore_results = ProdStore.objects.filter(
            store__name__icontains=self.search
        )
        products = Products.objects.filter(
            prodstore__in=prodstore_results
        ).distinct()

        return products

    def get_products_by_name(self):
        """Return products found by name"""

        products = Products.objects.filter(
            name__icontains=self.search
        ).distinct()

        return products

    def get_all_products(self):
        """Return search result found by name, category, brand & store"""

        products_by_category = self.get_products_by_category()
        products_by_brand = self.get_products_by_brand()
        products_by_store = self.get_products_by_store()
        products_by_name = self.get_products_by_name()

        products = products_by_name.union(
            products_by_category,
            products_by_brand,
            products_by_store
        ).distinct()

        return products

class CheckProduct():
    """Check if registered product in database"""

    def __init__(self, code):
        self.code = code
        self.product = self.check()

    def check(self):
        """
        Check if registered product
        """
        try:
            product = Products.objects.get(
                code=self.code
            )
        except Products.DoesNotExist:
            product = None

        return product

    def get_brands(self):
        """Return main and list of all brands of a product"""

        prodbrand_results = ProdBrand.objects.filter(
            product__code=self.code
        )
        brands = [brand.brand.name for brand in prodbrand_results]
        brand = prodbrand_results[0].brand.name

        return brand, brands

    def get_stores(self):
        """Return list of all stores of a product"""

        prodstore_results = ProdStore.objects.filter(
            product__code=self.code
        )
        stores = [store.store.name for store in prodstore_results]

        return stores

    def get_categories(self):
        """Return list of all categories of a product"""

        prodcategory_results = ProdCat.objects.filter(
            product__code=self.code
        ).exclude(
            category__name=Products.objects.get(code=self.code).compare_to_category.name
        )
        categories = {}
        for category in prodcategory_results:
            categories[category.category.name] = category.category.name_fr

        return categories

    def get_alternatives(self):
        """Return alternatives of a product and redirect to product page"""

        alternatives = Products.objects.filter(
            compare_to_category=self.product.compare_to_category,
            nutriscore__lte=self.product.nutriscore
        ).exclude(
            code=self.code
        ).distinct().order_by('nutriscore')

        return alternatives


class UserProducts():
    """Return user registered products"""

    def __init__(self, user):
        self.user = user

    def get_user_products(self):
        """Return user registered products"""

        user_products = UserSave.objects.filter(
            user=self.user
        )
        products = Products.objects.filter(
            usersave__in=user_products
        ).distinct().order_by('nutriscore')

        return products
