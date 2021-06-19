"""User"""
import json

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views.generic import TemplateView
from django.views.generic.base import ContextMixin
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from .forms import ConnectionForm, NewForm
from .models import User
from .validators import validate_username


class UserFormContext(ContextMixin):
    """User form"""

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form_user'] = ConnectionForm()
        return context


class LoginView(TemplateView):
    """View to login User"""

    template_name = "/"

    form_user = ConnectionForm()

    def post(self, request, **kwargs):
        """User login from HTML form"""

        user_login = request.POST.get('connect-user_login', False)
        password = request.POST.get('connect-pwd', False)
        user = authenticate(username=user_login, password=password)
        if user is not None and user.is_active:
            login(request, user)

            if request.META.get('HTTP_REFERER') is not None:
                redirect_path = request.META.get('HTTP_REFERER')
            else:
                redirect_path = '/'

            return redirect(redirect_path)
        else:
            return render(request, 'user/new_account.html')


class LogoutView(TemplateView):
    """Logout User"""

    template_name = "/"

    def get(self, request, **kwargs):

        logout(request)

        return redirect(self.template_name)


class UserAccountView(LoginRequiredMixin, TemplateView):
    """View to show user account"""

    template_name = "/"

    def get(self, request, **kwargs):

        form_user = ConnectionForm()

        return render(
            request,
            'user/user.html',
            {
                "form_user": form_user
            }
        )


class NewAccountView(TemplateView):
    """View to register new use"""

    template_name = "/"

    def get(self, request, **kwargs):
        """Access new account page"""

        form_new = NewForm()
        form_user = ConnectionForm()

        return render(
            request,
            'user/new_account.html',
            {
                "form_new": form_new,
                "form_user": form_user
            }
        )

    def post(self, request, **kwargs):
        """Register new user and redirect to user account"""

        data = {'ok': False}
        form_new = NewForm(request.POST)
        if form_new.is_valid():
            email = form_new.cleaned_data["email"]
            if CheckEmailView.check_email(self, email, check_available=True):
                pwd = form_new.cleaned_data["pwd"]
                pwd_confirm = form_new.cleaned_data["pwd_confirm"]
                user_login = form_new.cleaned_data["user_login"]
                if user_login == '':
                    user_login = email
                firstname = form_new.cleaned_data["firstname"]
                lastname = form_new.cleaned_data["lastname"]
                # newsletter = form_new.cleaned_data["newsletter"]
                user = User.objects.create_user(
                    email,
                    password=pwd,
                    username=user_login,
                    first_name=firstname,
                    last_name=lastname
                )
                user.save()
                data['ok'] = True
            else:
                data['email'] = False
        else:
            try:
                validate_email(form_new.cleaned_data["email"])
            except:
                data['email'] = False
            try:
                pwd = form_new.cleaned_data["pwd"]
                pwd_confirm = form_new.cleaned_data["pwd_confirm"]
                assert pwd == pwd_confirm
            except:
                data['pwd'] = False

        if data['ok']:
            new_user = authenticate(
                request,
                username=email,
                password=pwd
            )
            if new_user is not None:
                login(request, new_user)
                data['url'] = reverse('user_account')

        return JsonResponse(data)

@method_decorator(csrf_exempt, name="dispatch")
class CheckLoginView(TemplateView):
    """
    Login check :
        - If not taken
        - If format is correct
    """
    template = '/'

    def post(self, request, **kwargs):
        """Login user from HTML form"""
        user_login = request.POST.get("user_login")

        if User.objects.filter(username=user_login).exists():
            return HttpResponse('login not available')
        else:
            try:
                validate_username(user_login)
                return HttpResponse('login ok')
            except ValidationError:
                return HttpResponse('Incorrect login format')

@method_decorator(csrf_exempt, name="dispatch")
class CheckEmailView(TemplateView):
    """
    Email check :
        - If not taken
        - If format is correct
    """
    template = '/'

    def post(self, request, **kwargs):
        """Retrieve email from HTML form"""
        email = request.POST.get('email')

        if self.check_email(email):
            return HttpResponse("email ok")
        else:
            return HttpResponse("email nok")

    def check_email(self, email, check_available=False):
        """Email check usable out of view"""
        if check_available:
            if User.objects.filter(email=email).exists():
                return False
        try:
            validate_email(email)
            return True
        except ValidationError:
            return False


@method_decorator(csrf_exempt, name="dispatch")
class CheckPwdView(TemplateView):
    """
    Pwd check :
        - If not too common
        - If format is correct :
            - contains at least one capital
            - contains at least one digit
            - contains at least 8 caracters
            - contains at least one special caracter

    """
    template = '/'

    def post(self, request, **kwargs):
        """Retrieve password from HTML form"""
        pwd = request.POST.get("pwd")

        try:
            validate_password(pwd)
        except ValidationError as err:
            return HttpResponse(json.dumps(err.messages))
        else:
            return HttpResponse("Mot de passe OK")
