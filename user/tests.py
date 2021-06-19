"""Module user.tests"""
from django.apps import apps
from django.test import TestCase, Client
from django.contrib.auth.hashers import make_password

from user.apps import UserConfig
from user.models import User
from user.validators import (
    CapitalValidator,
    DigitValidator,
    SpecialCharacterValidator
)


class UserConfigTest(TestCase):
    """Testing user app"""

    def test_app_(self):
        """Test app name"""
        self.assertEqual(
            UserConfig.name,
            'user'
        )
        self.assertEqual(
            apps.get_app_config('user').name,
            'user'
        )

class NewAccountViewTest(TestCase):
    """Testing new account page"""

    def setUp(self):
        """Setup new account test"""
        self.email = 'foo@test.com'
        self.pwd = 'Pwd4Test!'

        self.user = {
            'email': self.email,
            'pwd': self.pwd,
            'pwd_confirm': self.pwd,
            'user_login': '',
            'firstname': '',
            'lastname': '',
            'cgu': True
        }

    def test_new_account_view(self):
        """Test get new user account view"""

        response = self.client.get('/user/new/')

        self.assertEqual(response.status_code, 200)

    def test_register_new_account(self):
        """Test to register new user"""

        user_login = self.client.login(
            username = self.email,
            password = self.pwd
        )
        self.assertEqual(user_login, False)

        self.client.post(
            '/user/create_new/',
            self.user
        )
        user_login = self.client.login(
            username = self.email,
            password = self.pwd
        )
        self.assertEqual(user_login, True)

    def test_already_exists_user(self):
        """
        Call twice to return invalid form
        Email already used
        """
        self.client.post(
            '/user/create_new/',
            self.user
        )
        response = self.client.post(
            '/user/create_new/',
            self.user
        )
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(
            str(response.content, encoding='utf8'),
            {
                'ok': False,
                'email': False
            }
        )

    def test_wrong_email(self):
        """
        Call with wrong email to return invalid form
        Email format not validated"""
        user_wrong_email = {
            'email': '@uihfur',
            'pwd': self.pwd,
            'pwd_confirm': self.pwd,
            'user_login': '',
            'firstname': '',
            'lastname': '',
            'cgu': True
        }
        response = self.client.post(
            '/user/create_new/',
            user_wrong_email
        )
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(
            str(response.content, encoding='utf8'),
            {
                'ok': False,
                'email': False
            }
        )

    def test_wrong_pwd(self):
        """
        Call with wrong pwd confirmation to return invalid form
        Password is not the same in both fields
        """
        invalid_pwd = 'khhiufr/'
        user_wrong_pwd = {
            'email': 'new_foo@example.com',
            'pwd': self.pwd,
            'pwd_confirm': invalid_pwd,
            'user_login': '',
            'firstname': '',
            'lastname': '',
            'cgu': True
        }
        response = self.client.post(
            '/user/create_new/',
            user_wrong_pwd
        )
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(
            str(response.content, encoding='utf8'),
            {
                'ok': False,
                'pwd': False
            }
        )


class LoginViewTest(TestCase):
    """Test login user"""

    def setUp(self):
        """Setup login test"""

        self.user = {
            'connect-user_login': 'foo@example.com',
            'connect-pwd': 'admin'
        }

    def test_login_user(self):
        """Test login view / redirect home page"""
        User.objects.create(
            username="admin",
            email="foo@example.com",
            password=make_password("admin")
        )
        client = Client()
        response = client.post(
            '/user/login/',
            self.user,
            follow=True
        )

        self.assertEqual(
            response.context['user'].is_authenticated,
            True
        )

    def test_login_with_redirect(self):
        """Test login view / redirect actual page"""
        User.objects.create(
            username="admin",
            email="foo@example.com",
            password=make_password("admin")
        )
        client = Client(
            HTTP_REFERER='/user/new/'
        )

        response = client.post(
            '/user/login/',
            self.user,
            follow=True
        )

        self.assertEqual(
            response.context['user'].is_authenticated,
            True
        )

    def test_login_bad_user(self):
        """Test login view / bad user"""
        User.objects.create(
            username="admin",
            email="foo@example.com",
            password=make_password("admin")
        )
        client = Client()
        response = client.post(
            '/user/login/',
            {
                'connect-user_login': 'bad_login',
                'connect-pwd': 'bad_pwd'
            },
            follow=True
        )

        self.assertEqual(
            response.context['user'].is_authenticated,
            False
        )

    def test_login_by_username_view(self):
        """Test get user account view"""
        User.objects.create_user(
            username='admin',
            email='foo@example.com',
            password='password'
        )
        login_user = self.client.login(
            username='admin',
            password='password'
        )
        self.assertEqual(
            login_user,
            True
        )

    def test_wrong_pwd_view(self):
        """Test get user account view"""
        User.objects.create_user(
            username='admin',
            email='foo@example.com',
            password='password'
        )
        login_user = self.client.login(
            username='foo@example.com',
            password='motdepasse'
        )
        self.assertEqual(
            login_user,
            False
        )


class LogoutViewTest(TestCase):
    """Test logout user"""

    def setUp(self):
        """setup logout test"""

        User.objects.create(
            username="admin",
            email="foo@example.com",
            password=make_password("admin")
        )
        self.user = {
            'connect-user_login': 'foo@example.com',
            'connect-pwd': 'admin'
        }

    def test_logout_user(self):
        """Test logout view"""

        login_user = self.client.login(
            username='foo@example.com',
            password='admin'
        )
        self.assertEqual(
            login_user,
            True
        )

        # TEST LOGOUT USER
        response = self.client.get(
            '/user/logout/',
            self.user,
            follow=True
        )

        self.assertEqual(
            response.context['user'].is_authenticated,
            False
        )

class UserAccountViewTest(TestCase):
    """Testing user account page"""

    def setUp(self):
        """setup user account test"""
        User.objects.create(
            username="admin",
            email="foo@example.com",
            password=make_password("admin")
        )

    def test_user_account_view(self):
        """Test get user account view"""

        login_user = self.client.login(
            username='foo@example.com',
            password='admin'
        )
        self.assertEqual(
            login_user,
            True
        )
        response = self.client.get('/user/my_account/')

        self.assertEqual(response.status_code, 200)

class UserLoginViewTest(TestCase):
    """Check user login View"""

    def setUp(self):
        """setup user login test"""
        self.user = User.objects.create_user(
            username='admin',
            email='foo@example.com',
            password=make_password('admin')
        )
        self.good_login = {
            'user_login': 'Admin'
        }
        self.login_exists = {
            'user_login': 'admin'
        }
        self.bad_login = {
            'user_login': '4dm!n'
        }

    def test_good_user_login(self):
        """Test user login"""
        response = self.client.post(
            '/user/check_user_login/',
            self.good_login
        )
        self.assertEqual(response.status_code, 200)

    def test_exists_user_login(self):
        """Test user login / already exists"""
        response = self.client.post(
            '/user/check_user_login/',
            self.login_exists
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            str(response.content, encoding='utf8'),
            'login not available'
        )

    def test_bad_user_login(self):
        """Test user login / bad format"""
        response = self.client.post(
            '/user/check_user_login/',
            self.bad_login
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            str(response.content, encoding='utf8'),
            'Incorrect login format'
        )

class EmailLoginViewTest(TestCase):
    """Check user email View"""

    def setUp(self):
        """Test email check"""
        self.good_email = {
            'email': 'foo@example.com'
        }
        self.bad_email = {
            'email': 'foo]example'
        }

    def test_good_email(self):
        """Test email check / good email"""
        response = self.client.post(
            '/user/email_verification/',
            self.good_email
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            str(response.content, encoding='utf8'),
            'email ok'
        )

    def test_bad_email(self):
        """Test email check / bad format email"""
        response = self.client.post(
            '/user/email_verification/',
            self.bad_email
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            str(response.content, encoding='utf8'),
            'email nok'
        )

# class CheckEmailViewTest(TestCase):
#     """Check user email View"""

#     def setUp(self):
#         self.bad_email = {
#             'email': 'foo]example'
#         }

#     def test_bad_email(self):
#         response = CheckEmailViewTest.check_email(self, self.bad_email, check_available=True)
#         self.assertEqual(
#             response,
#             False
#         )

class CheckPwdViewTest(TestCase):
    """Check user pwd View"""

    def setUp(self):
        """Test pwd check"""
        self.good_pwd = {
            'pwd': 'Pwd4Test!'
        }
        self.bad_pwd = {
            'pwd': 'password'
        }

    def test_bad_pwd(self):
        """Test pwd check / bad format pwd"""
        response = self.client.post(
            '/user/check_pwd/',
            self.bad_pwd
        )
        self.assertEqual(response.status_code, 200)
        # Check if all error messages are in resonse
        error_msgs = [
            'This password must contain at least one capital.',
            'This password must contain at least one digit.',
            'This password must contain at least one special caracter.',
            'This password is too common'
        ]
        for message in error_msgs:
            self.assertIn(
                message,
                str(response.content, encoding='utf8')
            )

        # Check for validators help texts
        self.assertEqual(
            CapitalValidator.get_help_text(self),
            'Your password must contain at least one capital'
        )
        self.assertEqual(
            DigitValidator.get_help_text(self),
            'Your password must contain at least one digit'
        )
        self.assertEqual(
            SpecialCharacterValidator.get_help_text(self),
            'Your password must contain at least one special caracter'
        )

    def test_good_pwd(self):
        """Test pwd check / good pwd"""
        response = self.client.post(
            '/user/check_pwd/',
            self.good_pwd
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            str(response.content, encoding='utf8'),
            'Mot de passe OK'
        )

class SuperUserTest(TestCase):
    """Test Superuser create"""

    def setUp(self):
        """setup superuser creation test"""
        self.user = User.objects.create_superuser(
            username='admin',
            email='foo@example.com',
            password=make_password('admin')
        )

    def test_superuser(self):
        """test superuser creation"""
        self.assertEqual(
            self.user.is_superuser,
            True
        )

    def test_wrong_staff_superuser(self):
        """test wrong staff superuser creation"""
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                username='admin',
                email='foo@example.com',
                password=make_password('admin'),
                is_staff=False
            )

    def test_wrong_superuser(self):
        """test wrong superuser superuser creation"""
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                username='admin',
                email='foo@example.com',
                password=make_password('admin'),
                is_superuser=False
            )
