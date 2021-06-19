"""Selenium tests"""
import time

from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.common.keys import Keys

from purbeurre.lib.silent_connection_reset import ConnectionResetErrorSwallowingLiveServerThread

class MySeleniumTests(StaticLiveServerTestCase):
    """Selenium tests class"""
    fixtures = [
        'users.json',
        'products.json',
    ]

    # Silent WinError 10054
    server_thread_class = ConnectionResetErrorSwallowingLiveServerThread

    @classmethod
    def setUpClass(cls):
        """Setup selenium tests"""
        super().setUpClass()
        cls.selenium = WebDriver(executable_path="C:/Users/mpe3661/AppData/Local/chromedriver")
        cls.selenium.maximize_window()

    @classmethod
    def tearDownClass(cls):
        """Close selenium driver tests"""

        cls.selenium.refresh()
        time.sleep(1)
        cls.selenium.quit()
        time.sleep(1)
        super().tearDownClass()

    def assert_home_page(self):
        """Check if homepage"""
        self.assertIn(
            'Du gras, oui, mais de qualité !',
            self.selenium.page_source
        )

    def product_search(self, form_id, search, result):
        """
        Fonction to search for a given *search*
        in *form* and check if *result* is in page_source
        """
        form_elmt = self.selenium.find_element_by_id(form_id)
        search_elmt = form_elmt.find_element_by_name('product_search')
        search_elmt.send_keys(search)
        search_elmt.send_keys(Keys.ENTER)
        self.assertIn(
            result,
            self.selenium.page_source
        )

    def get_home(self):
        """Test get home page"""
        self.selenium.get(self.live_server_url)
        time.sleep(1)

    def test_get_home(self):
        """Test get home page"""
        self.get_home()
        self.assertIn(
            'Pur Beurre',
            self.selenium.title
        )
        self.assert_home_page()

    def test_search_not_found_header(self):
        """
        Search non-existent product
        on header searchbar from homepage
        """
        self.get_home()
        self.product_search(
            'searchbar',
            'no_product',
            'Aucun produit'
        )

    def test_search_not_found_input_homepage(self):
        """
        Search non-existent product
        on input homepage from homepage
        """
        self.get_home()
        self.product_search(
            'home_product_search',
            'no_product',
            'Aucun produit'
        )

    def test_search_found_header(self):
        """
        Search existent product
        on header searchbar from homepage
        """
        self.get_home()
        self.product_search(
            'searchbar',
            'nutella',
            'Un seul produit'
        )

    def test_search_found_input_homepage(self):
        """
        Search existent product
        on header searchbar from homepage
        """
        self.get_home()
        self.product_search(
            'home_product_search',
            'nutella',
            'Un seul produit'
        )

    def test_get_contact(self):
        """
        Click on #contact and check page
        """
        self.get_home()
        element = self.selenium.find_element_by_partial_link_text(
            'Contact'
        )
        element.click()

    def test_get_legals(self):
        """
        Click on #legal and check page
        """
        self.get_home()
        element = self.selenium.find_element_by_partial_link_text(
            'Mentions légales'
        )
        element.click()
        self.assertIn(
            'différentes modalités',
            self.selenium.page_source
        )

    def connect_user(self):
        """Connect a user with selenium"""
        element = self.selenium.find_element_by_id(
            'login_user'
        )
        element.click()
        time.sleep(1)
        element_form = self.selenium.find_element_by_id(
            'form_user_connect'
        )
        element_login = element_form.find_element_by_name(
            'connect-user_login'
        )
        element_login.send_keys('admin')
        element_pwd = element_form.find_element_by_name(
            'connect-pwd'
        )
        element_pwd.send_keys('admin')
        element_button = element_form.find_element_by_id(
            'btn_connect'
        )
        element_button.click()

    def test_connect_user(self):
        """
        Click on *user_account* and check page
        """
        self.get_home()
        self.connect_user()
        self.assertIn(
            'Mon compte',
            self.selenium.page_source
        )

    def test_logout_user(self):
        """
        Click on *user_account* and check page
        """
        self.get_home()
        self.connect_user()
        self.assertIn(
            'Mon compte',
            self.selenium.page_source
        )
        element = self.selenium.find_element_by_id(
            'logout_user'
        )
        element.click()
        self.assertNotIn(
            'Mon compte',
            self.selenium.page_source
        )

    def test_user_account(self):
        """
        Click on *user_account* and check page
        """
        self.get_home()
        self.connect_user()
        element = self.selenium.find_element_by_id(
            'user_account'
        )
        element.click()
        self.assertIn(
            'Informations utilisateur',
            self.selenium.page_source
        )

    def test_user_products(self):
        """
        Click on *user products* and check page
        """
        self.get_home()
        self.connect_user()
        element = self.selenium.find_element_by_id(
            'user_products'
        )
        element.click()
        self.assertIn(
            "Aucun produit",
            self.selenium.page_source
        )

    def get_product_page(self):
        """Click on first clickable product in this page"""
        time.sleep(1)
        products = self.selenium.find_elements_by_class_name('product-link')
        products[0].click()
        self.assertIn(
            "Afficher les informations de ce produit",
            self.selenium.page_source
        )

    def test_get_product_page(self):
        """
        Search existent product
        on header searchbar from homepage
        """
        self.get_home()
        self.product_search(
            'home_product_search',
            'nutella',
            'Un seul produit'
        )
        self.get_product_page()

    def test_save_product(self):
        """
        1. Connect user
        2. Access to my products to check no products saved
        3. Access to a product and save it
        4. Access to my products and check product is registered
        """
        self.get_home()
        self.connect_user()

        # Click on user *my_products* and check no products registered
        element = self.selenium.find_element_by_id(
            'user_products'
        )
        element.click()
        self.assertIn(
            "Aucun produit enregistré",
            self.selenium.page_source
        )
        self.get_home()
        self.product_search(
            'searchbar',
            'nutella',
            'Un seul produit'
        )
        self.get_product_page()

        # Page down to able click on save product
        time.sleep(1)
        self.selenium.execute_script("window.scrollTo(0, 400)")

        # Select save product & click it
        time.sleep(1)
        element = self.selenium.find_elements_by_class_name(
            'save-product'
        )
        element[0].click()

        # Click on user *my_products* and check product is registered
        time.sleep(1)
        self.get_home()
        element = self.selenium.find_element_by_id(
            'user_products'
        )
        element.click()
        self.assertNotIn(
            "Aucun produit enregistré",
            self.selenium.page_source
        )
