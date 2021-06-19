"""command methods"""
import string
import requests

from products.models import (
    Products,
    Categories,
    RelatedCategories,
    ProdCat,
    Brands,
    ProdBrand,
    Stores,
    ProdStore
)


class DatabaseCount():
    """Count lines in database (Heroku limit)"""
    count = 0

    def new_entry(self):
        """+1 line"""
        DatabaseCount.count += 1

class ImportCategories(DatabaseCount):
    """Import categories in DB"""

    def __init__(self):
        """Request OpenFoodFacts API and import categories"""

        self.url = "https://fr.openfoodfacts.org/categories.json"


    def initiate_db(self):
        """Initiate database"""

        all_categories = self.request_categories(self.url)
        self.import_categories(all_categories)
        self.all = Categories.objects.all()

    def request_categories(self, request_url):
        """Request OpenFoodFacts to retrieve all categories"""

        resp = requests.get(request_url)

        return resp.json()

    def import_categories(self, all_categories):
        """Loop on all_categories JSON to test if importable and import if OK"""

        i = 0
        while (
            i < len(all_categories['tags'])
            and all_categories['tags'][i]['products'] > 1000
        ):
            category = all_categories['tags'][i]
            if self.test_category(category):
                self.create_category(category)
            i += 1

    def test_category(self, category):
        """Test if category is importable"""

        importable = False
        try:
            Categories.objects.get(
                name=category['id'].split(':')[1]
            )
        except Categories.DoesNotExist:
            importable = True
        except:
            importable = False

        return importable

    def create_category(self, category):
        """Import category in products_categories"""

        super().new_entry()

        return Categories.objects.create(
            name=category['id'].split(':')[1],
            name_fr=category['name'],
            url=category['url']
        )

class Category(DatabaseCount):
    """From Queryset"""

    def __init__(self, category):
        self.category = category

    def get_products_list(self, pages=1):
        """Get products list"""

        list_products = []
        for i in range(pages):
            page = str(i + 1)
            request_url = self.category.url
            request_url += '/etat/complet/{}.json'.format(page)
            resp = requests.get(request_url)

            list_products += resp.json()['products']

        return list_products


class ProductImportation(DatabaseCount):
    """Import a product in DB"""

    list_nutriments = [
        "energy-kcal_100g",
        "fat_100g",
        "saturated-fat_100g",
        "carbohydrates_100g",
        "sugars_100g",
        "fiber_100g",
        "proteins_100g",
        "salt_100g",
        "sodium_100g"
    ]
    codes = []
    count = 0

    def __init__(self, product):
        """Check if product is importable and import it."""

        self.codes = list(
            Products.objects.all().values_list(
                'code',
                flat=True
            )
        )

        self.product = product
        self._check_product()
        if self.importable:
            self.product_object = self.import_in_db()
            self.categories = self.create_categories()
            self.brands = self.import_brands()
            self.stores = self.import_stores()

    def _check_product(self):
        """Return True if product is importable."""

        self.importable = False
        abcde = string.ascii_uppercase[:5]
        product_infos = self.retrieve_product_infos()

        if product_infos['product_code'] is not None:
            try:
                Products.objects.get(
                    code=product_infos['product_code']
                )
            except Products.DoesNotExist:
                if (
                    product_infos['product_name'] is not None
                    and product_infos['product_code'] not in ProductImportation.codes
                    and product_infos['product_code'] is not None
                    and product_infos['product_url'] is not None
                    and product_infos['image_url'] is not None
                    and product_infos['quantity'] is not None
                    and product_infos['ingredients'] is not None
                    and product_infos['brands'] != []
                    and product_infos['stores'] != []
                    and product_infos['countries'] is not None
                    and product_infos['compare_to'] is not None
                    and product_infos['categories_hierarchy'] is not None
                    and product_infos['nutriscore'] in abcde
                    and all([product_infos[nutriment] >= 0 for nutriment in self.list_nutriments])
                    and Categories.objects.filter(name=product_infos['compare_to']).count() > 0
                ):
                    self.name = product_infos['product_name']
                    self.product_infos = product_infos
                    self.code = product_infos['product_code']
                    ProductImportation.codes.append(self.code)
                    self.importable = True

        return self.importable

    def retrieve_product_infos(self):
        """Retrieve product infos from JSON"""

        # PRODUCT NAME
        try:
            product_name = self.product['product_name'].capitalize()
        except KeyError:
            product_name = None

        # PRODUCT CODE
        try:
            product_code = self.product['code'].capitalize()
        except KeyError:
            product_code = None

        # URL
        try:
            product_url = self.product['url'].lower()
        except KeyError:
            product_url = None

        # IMAGE URL
        try:
            image_url = self.product['image_url'].lower()
        except KeyError:
            image_url = None

        # QUANTITY
        try:
            quantity = self.product['quantity'].capitalize()
        except KeyError:
            quantity = None

        # INGREDIENTS
        try:
            ingredients = self.product['ingredients_text_fr'].capitalize()
        except KeyError:
            ingredients = None

        # BRAND
        brands = []
        try:
            for brand in self.product['brands'].split(','):
                brand = brand.strip().capitalize()
                if (
                    brand != ''
                    and brand not in brands
                ):
                    brands.append(brand)
        except KeyError:
            pass

        # STORES
        stores = []
        try:
            for store in self.product['stores'].split(','):
                store = store.strip().capitalize()
                if (
                    store != ''
                    and store not in stores
                ):
                    stores.append(store)
        except KeyError:
            pass

        # COUNTRY
        try:
            countries = self.product['countries'].capitalize()
        except KeyError:
            countries = None
        if 'France' in countries:
            countries = 'France'
        else:
            countries = None

        # COMPARE TO CATEGORY
        try:
            compare_to = self.product['compared_to_category'].capitalize().split(':')[1]
        except KeyError:
            compare_to = None
        try:
            Categories.objects.get(
                name=compare_to
            )
        except Categories.DoesNotExist:
            compare_to = None
        except:
            importable = False

        # CATEGORIES HIERARCHY
        try:
            categories_hierarchy = [
                category.split(':')[1] for category in self.product['categories_hierarchy']
            ]
        except KeyError:
            categories_hierarchy = None

        # NUTRISCORE GRADE
        nutriscore_labels = [
            'nutrition_grade_fr',
            'nutriscore_grade'
        ]
        nutriscore = 'F'
        i = 0
        while (
            i < len(nutriscore_labels)
            and nutriscore == 'F'
        ):
            try:
                nutriscore = self.product[nutriscore_labels[i]].upper()
            except KeyError:
                i += 1

        product_infos = {
            'product_name': product_name,
            'product_code': product_code,
            'product_url': product_url,
            'image_url': image_url,
            'quantity': quantity,
            'ingredients': ingredients,
            'brands': brands,
            'stores': stores,
            'countries': countries,
            'compare_to': compare_to,
            'categories_hierarchy': categories_hierarchy,
            'nutriscore': nutriscore
        }

        nutriments = self.product['nutriments']
        for nutriment in self.list_nutriments:
            try:
                product_infos[nutriment] = float(nutriments[nutriment])
            except KeyError:
                product_infos[nutriment] = 0

        return product_infos

    def import_in_db(self):
        """Import product in purbeurre DB"""

        super().new_entry()

        if Categories.objects.all().count() > 0:
            try:
                category_compare = Categories.objects.get(
                    name=self.product_infos['compare_to']
                )
            except:
                category_compare = None
        else:
            category_compare = None

        product_object = Products.objects.create(
            code=self.code,
            name=self.name,
            url=self.product_infos['product_url'],
            quantity=self.product_infos['quantity'],
            country=self.product_infos['countries'],
            ingredients=self.product_infos['ingredients'],
            energy=self.product_infos['energy-kcal_100g'],
            fat=self.product_infos['fat_100g'],
            satured_fat=self.product_infos['saturated-fat_100g'],
            carbohydrates=self.product_infos['carbohydrates_100g'],
            sugar=self.product_infos['sugars_100g'],
            fibers=self.product_infos['fiber_100g'],
            proteins=self.product_infos['proteins_100g'],
            salt=self.product_infos['salt_100g'],
            sodium=self.product_infos['sodium_100g'],
            nutriscore=self.product_infos['nutriscore'],
            image_url=self.product_infos['image_url'],
            compare_to_category=category_compare
        )

        ProductImportation.count += 1

        return product_object

    def create_categories(self):
        """
        From product list of categories:
          - Check if relation exists between parent and child category
          - Create link between product and its category
        """

        categories = self.product_infos['categories_hierarchy']

        i = 0
        for category in categories:
            try:
                parent_category = Categories.objects.get(
                    name=category
                )
                product_category = ProdCat.objects.get(
                    category=parent_category,
                    product=self.product_object
                )
            except Categories.DoesNotExist:
                pass
            except ProdCat.DoesNotExist:
                super().new_entry()
                ProdCat.objects.create(
                    product=self.product_object,
                    category=parent_category
                )
            except:
                pass
            if i < len(self.product_infos['categories_hierarchy']) - 1:
                try:
                    child_category = Categories.objects.get(
                        name=self.product_infos['categories_hierarchy'][i+1]
                    )
                    RelatedCategories.objects.get(
                        parent=parent_category,
                        child=child_category
                    )
                except RelatedCategories.DoesNotExist:
                    super().new_entry()
                    RelatedCategories.objects.create(
                        parent=parent_category,
                        child=child_category
                    )
                except Categories.DoesNotExist:
                    pass
                except:
                    pass
            i += 1

        return categories

    def import_brands(self):
        """
        - Retrieve product brands
        - Check if exists in DB and import if not
        - Create link in ProdBrand DB
        """

        brands = self.product_infos['brands']

        for product_brand in brands:
            try:
                brand = Brands.objects.get(
                    name=product_brand
                )
            except Brands.DoesNotExist:
                super().new_entry()
                brand = Brands.objects.create(
                    name=product_brand
                )
            except:
                pass
            try:
                ProdBrand.objects.get(
                    product=self.product_object,
                    brand=brand
                )
            except ProdBrand.DoesNotExist:
                super().new_entry()
                ProdBrand.objects.create(
                    product=self.product_object,
                    brand=brand
                )
            except:
                pass

        return brands

    def import_stores(self):
        """
        - Retrieve product stores
        - Check if exists in DB and import if not
        - Create link in ProdBrand DB
        """

        stores = self.product_infos['stores']

        for product_store in stores:
            try:
                store = Stores.objects.get(
                    name=product_store
                )
            except Stores.DoesNotExist:
                super().new_entry()
                store = Stores.objects.create(
                    name=product_store
                )
            except:
                pass
            try:
                ProdStore.objects.get(
                    product=self.product_object,
                    store=store
                )
            except ProdStore.DoesNotExist:
                super().new_entry()
                ProdStore.objects.create(
                    product=self.product_object,
                    store=store
                )
            except:
                pass

        return stores
