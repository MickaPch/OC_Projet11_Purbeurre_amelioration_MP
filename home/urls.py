"""Module home.urls"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.HomeView.as_view(), name="home_page"),
    path('legal_notice/', views.LegalNoticeView.as_view(), name="legal_notice"),
]
