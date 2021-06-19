"""Module home.views"""
from django.views.generic import TemplateView

from user.views import UserFormContext
from products.views import ProductFormContext


class HomeView(TemplateView, ProductFormContext, UserFormContext):
    """Home view"""

    template_name = "home/home.html"


class LegalNoticeView(TemplateView, ProductFormContext, UserFormContext):
    """Legal notice view"""

    template_name = 'home/legal_notice.html'
