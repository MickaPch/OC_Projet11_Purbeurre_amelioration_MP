"""Products views"""
from django.shortcuts import redirect
from django.views.generic import TemplateView, View, FormView
from django.views.generic.base import ContextMixin
from django.contrib.auth.mixins import LoginRequiredMixin

from products.forms import SearchForm, SaveForm, DeleteForm
from products.queries import GetProductsQueryTool, CheckProduct, UserProducts
from user.views import UserFormContext


class ProductFormContext(ContextMixin):
    """Product search form"""

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['search_form'] = SearchForm(
            auto_id=False
        )
        return context


class SearchFormRedirect(View):
    """Search for products in database"""

    def post(self, request, **kwargs):
        """Search product in database from HTML POST"""

        search_form = SearchForm(
            request.POST,
            auto_id=False
        )

        if search_form.is_valid():
            search = search_form.cleaned_data['product_search']
            check_product = CheckProduct(search)
            if check_product.product is not None:
                return redirect(f'/products/product/{search}/')
            else:
                return redirect(f'/products/search/{search}/')
        else:
            return redirect('/')


class ProductsViews(TemplateView, ProductFormContext, UserFormContext):
    """View to show searched products"""

    template_name = "products/search.html"

    def get_context_data(self, **kwargs):

        context = super().get_context_data(**kwargs)
        search = kwargs['search']
        context['search_form'] = SearchForm(
            initial={'product_search': search},
            auto_id=False
        )
        return context

class AllProductsView(ProductsViews):
    """View to show searched products"""

    def get_context_data(self, **kwargs):

        context = super().get_context_data(**kwargs)
        search = kwargs['search']

        context['search_type'] = 'search'
        products_querytool = GetProductsQueryTool(search)
        context['products'] = products_querytool.get_all_products()

        return context


class BrandView(ProductsViews):
    """View to show searched products"""

    def get_context_data(self, **kwargs):

        context = super().get_context_data(**kwargs)
        brand = kwargs['search']

        context['search_type'] = 'brand'
        products_querytool = GetProductsQueryTool(brand)
        context['products'] = products_querytool.get_products_by_brand()

        return context


class CategoryView(ProductsViews):
    """View to show searched products"""

    def get_context_data(self, **kwargs):

        context = super().get_context_data(**kwargs)
        category = kwargs['search']

        context['search_type'] = 'category'
        products_querytool = GetProductsQueryTool(category)
        context['products'] = products_querytool.get_products_by_category()

        return context


class StoreView(ProductsViews):
    """View to show searched products"""

    def get_context_data(self, **kwargs):

        context = super().get_context_data(**kwargs)
        store = kwargs['search']

        context['search_type'] = 'store'
        products_querytool = GetProductsQueryTool(store)
        context['products'] = products_querytool.get_products_by_store()

        return context


class ProductView(TemplateView, ProductFormContext, UserFormContext):
    """View to show searched products"""

    template_name = "products/product.html"

    def get_context_data(self, **kwargs):


        context = super().get_context_data(**kwargs)
        product_code = kwargs['search']
        context['search_form'] = SearchForm(
            initial={'product_search': product_code},
            auto_id=False
        )

        check_product = CheckProduct(product_code)
        if check_product.product is not None:
            context['product'] = check_product.product
            context['brand'], context['brands'] = check_product.get_brands()
            context['stores'] = check_product.get_stores()
            context['categories'] = check_product.get_categories()
            context['alternatives'] = check_product.get_alternatives()

        if self.request.user.is_authenticated:
            user_products = UserProducts(self.request.user)
            context['user_products'] = user_products.get_user_products()

        return context


class MyProductsView(
    LoginRequiredMixin,
    TemplateView,
    ProductFormContext,
    UserFormContext
):
    """View to show searched products"""

    template_name = "products/my_products.html"

    def get_context_data(self, **kwargs):

        context = super().get_context_data(**kwargs)
        user_products = UserProducts(self.request.user)
        context['products'] = user_products.get_user_products()

        return context


class SaveView(LoginRequiredMixin, FormView):
    """Save selected products"""

    template_name = "products/save.html"
    form_class = SaveForm
    success_url = "/products/my_products/"

    def form_valid(self, form):

        form.save_products(self.request.user)

        return super().form_valid(form)


class DeleteView(LoginRequiredMixin, FormView):
    """Delete selected products"""

    template_name = "products/delete.html"
    form_class = DeleteForm
    success_url = "/products/my_products/"

    def form_valid(self, form):

        form.delete_products(self.request.user)

        return super().form_valid(form)
