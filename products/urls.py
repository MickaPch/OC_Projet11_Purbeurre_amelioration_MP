"""Products urls"""
from django.urls import path
from . import views

urlpatterns = [
    path('search', views.SearchFormRedirect.as_view(), name="search"),
    path('search/<str:search>/', views.AllProductsView.as_view(), name="products_search"),
    path('brand/<str:search>/', views.BrandView.as_view(), name="brand_search"),
    path('category/<str:search>/', views.CategoryView.as_view(), name="category_search"),
    path('store/<str:search>/', views.StoreView.as_view(), name="store_search"),
    path('product/<str:search>/', views.ProductView.as_view(), name="product"),
    path('save', views.SaveView.as_view(), name="save"),
    path('delete', views.DeleteView.as_view(), name="delete"),
    path('my_products/', views.MyProductsView.as_view(), name="my_products"),
]
