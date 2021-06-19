"""Import datas from OpenFoodFacts in database"""
from django.core.management.base import BaseCommand

from products.management.commands.lib import (
    ImportCategories,
    ProductImportation,
    DatabaseCount,
    Category
)


class Command(BaseCommand):
    """Import datas"""

    def handle(self, *args, **kwargs):
        """import command"""

        categories = ImportCategories()

        categories.initiate_db()

        i = 0
        while (
            i < categories.all.count()
            and DatabaseCount.count < 9000
        ):
            category = Category(categories.all[i])
            products = category.get_products_list(pages=5)

            for product in products:
                # No products limit
                ProductImportation(product)

            i += 1
