"""Create JSON fixture products"""
import os
import json

from django.core.management.base import BaseCommand

class Command(BaseCommand):
    """Command to create products fixtures for tests"""

    def handle(self, *args, **kwargs):
        """Create products fixtures"""

        products = [
            {
                "model": "products.Products",
                "pk": 1,
                "fields": {
                    "code": "3017620422003",
                    "name": "Nutella pate a tartiner aux noisettes et au cacao",
                    "url": "https://fr.openfoodfacts.org/produit/3017620422003/nutella-pate-a-tartiner-aux-noisettes-et-au-cacao-ferrero",
                    "quantity": "400 g",
                    "country": "France",
                    "ingredients": "Sucre, huile de palme, _noisettes_ 13%, _lait_ écrémé en poudre 8,7%, cacao maigre 7,4%, émulsifiants: lécithines [_soja_] ; vanilline. Sans gluten",
                    "energy": 2252,
                    "fat": 30.9,
                    "satured_fat": 10.6,
                    "carbohydrates": 57.5,
                    "sugar": 56.3,
                    "fibers": 0,
                    "proteins": 6.3,
                    "salt": 0.107,
                    "sodium": 0.0428,
                    "nutriscore": "D",
                    "image_url": "https://static.openfoodfacts.org/images/products/301/762/042/2003/front_fr.248.400.jpg",
                    "compare_to_category": "en:sugary-cooking-helpers"
                }
            },
            {
                "model": "products.Products",
                "pk": 2,
                "fields": {
                    "code": "11111111111",
                    "name": "Test alternative 1",
                    "url": "https://fr.openfoodfacts.org/produit/XXXXXXXX",
                    "quantity": "XXX g",
                    "country": "France",
                    "ingredients": "ingredients",
                    "energy": 1111,
                    "fat": 25,
                    "satured_fat": 8,
                    "carbohydrates": 400,
                    "sugar": 40,
                    "fibers": 0,
                    "proteins": 5,
                    "salt": 0.05,
                    "sodium": 0.02,
                    "nutriscore": "C",
                    "image_url": "https://static.openfoodfacts.org/images/products/XXXXXXX.jpg",
                    "compare_to_category": "en:sugary-cooking-helpers"
                }
            },
            {
                "model": "products.Products",
                "pk": 3,
                "fields": {
                    "code": "22222222222",
                    "name": "Test alternative 2",
                    "url": "https://fr.openfoodfacts.org/produit/XXXXXXXX",
                    "quantity": "XXX g",
                    "country": "France",
                    "ingredients": "ingredients",
                    "energy": 2222,
                    "fat": 50,
                    "satured_fat": 16,
                    "carbohydrates": 800,
                    "sugar": 80,
                    "fibers": 0,
                    "proteins": 10,
                    "salt": 0.1,
                    "sodium": 0.08,
                    "nutriscore": "E",
                    "image_url": "https://static.openfoodfacts.org/images/products/XXXXXXX2.jpg",
                    "compare_to_category": "en:sugary-cooking-helpers"
                }
            },
            {
                "model": "products.Categories",
                "pk": 1,
                "fields": {
                    "name": "en:sugary-cooking-helpers",
                    "name_fr": "Aide culinaire sucrée",
                    "url": "https://fr.openfoodfacts.org/categorie/aide-culinaire-sucree",
                }
            },
            {
                "model": "products.Categories",
                "pk": 2,
                "fields": {
                    "name": "en:test-category",
                    "name_fr": "Category test",
                    "url": "https://www.openfoodfacts.fr",
                }
            },
            {
                "model": "products.Stores",
                "pk": 1,
                "fields": {
                    "name": "Store",
                }
            },
            {
                "model": "products.Stores",
                "pk": 2,
                "fields": {
                    "name": "Store Test",
                }
            },
            {
                "model": "products.Brands",
                "pk": 1,
                "fields": {
                    "name": "Brand",
                }
            },
            {
                "model": "products.Brands",
                "pk": 2,
                "fields": {
                    "name": "Brand Test",
                }
            },
            {
                "model": "products.ProdCat",
                "pk": 1,
                "fields": {
                    "product": "3017620422003",
                    "category": "en:sugary-cooking-helpers",
                }
            },
            {
                "model": "products.ProdCat",
                "pk": 2,
                "fields": {
                    "product": "3017620422003",
                    "category": "en:test-category",
                }
            },
            {
                "model": "products.ProdStore",
                "pk": 1,
                "fields": {
                    "product": "3017620422003",
                    "store": 1,
                }
            },
            {
                "model": "products.ProdStore",
                "pk": 2,
                "fields": {
                    "product": "3017620422003",
                    "store": 2,
                }
            },
            {
                "model": "products.ProdBrand",
                "pk": 1,
                "fields": {
                    "product": "3017620422003",
                    "brand": 1,
                }
            },
            {
                "model": "products.ProdBrand",
                "pk": 2,
                "fields": {
                    "product": "3017620422003",
                    "brand": 2,
                }
            }
        ]
        path_file = os.path.join(
            os.path.dirname(
                os.path.dirname(
                    os.path.dirname(__file__)
                )
            ),
            'fixtures',
            'products.json'
        )

        with open(path_file, 'w') as file_fixture:
            file_fixture.write(json.dumps(products))
