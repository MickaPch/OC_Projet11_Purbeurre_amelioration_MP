import requests

import os
import json

from django.db import connection


def truncate_table(table):
    """Truncate tables to import new products"""

    cursor = connection.cursor()

    sql_command = 'BEGIN;'
    sql_command += 'ALTER TABLE {} DISABLE TRIGGER ALL;'.format(table)
    sql_command += 'TRUNCATE TABLE {} CASCADE;'.format(table)
    sql_command += 'ALTER TABLE {} ENABLE TRIGGER ALL;'.format(table)
    sql_command += 'COMMIT;'

    return cursor.execute(sql_command)



def list_products(category):
    """Get a JSON list of products from OpenFoodFacts by category"""

    # Search in each category for importable products
    conditions = {
        'page_size': 100,
        'format': 'json',
        'sort_by': 'unique_scans_n',
        'criteria': [
            {
                'tagtype': 'categories',
                'tagcontains': 'contains'
            }, {
                'tagtype': 'states',
                'tag_contains': 'does_not_contains',
                'fixed_tag': 'to-be-completed'
            }, {
                'tagtype': 'countries',
                'tag_contains': 'contains'
            }
        ]
    }

    request_url = "https://fr.openfoodfacts.org/cgi/search.pl?action=process"

    conditions_path = os.path.join(
        os.path.dirname(
            os.path.dirname(
                os.path.dirname(__file__)
            )
        ),
        'static',
        'json',
        'category_conditions.json'
    )

    with open(conditions_path, 'r') as jsonf:
        conditions = json.load(jsonf)

    # Add criterias to request :
    for data in conditions['criteria']:
        i = conditions['criteria'].index(data)
        request_url += "&tagtype_{index}={tagtype}".format(
            index=str(i),
            tagtype=data['tagtype']
        )
        request_url += "&tag_contains_{index}={contains}".format(
            index=str(i),
            contains=data['tag_contains']
        )
        if data['tagtype'] == 'categories':
            request_url += "&tag_{index}={category}".format(
                index=str(i),
                category=category
            )
        else:
            request_url += "&tag_{index}={tag}".format(
                index=str(i),
                tag=data['contains']
            )

    # Add sorting
    request_url += "&sort_by={}".format(
        conditions['sort_by']
    )

    # Add page size
    request_url += "&page_size={}".format(
        conditions['page_size']
    )

    # Add file format
    request_url += "&{}=1".format(
        conditions['format']
    )

    resp = requests.get(request_url)

    return resp.json()['products']
