"""User urls"""
from django.urls import path
from . import views

urlpatterns = [
    path('my_account/', views.UserAccountView.as_view(), name="user_account"),
    path('login/', views.LoginView.as_view(), name="login"),
    path('logout/', views.LogoutView.as_view(), name="logout_user"),
    path('new/', views.NewAccountView.as_view(), name="new_account"),
    path('create_new/', views.NewAccountView.as_view(), name="create_new"),
    path('check_user_login/', views.CheckLoginView.as_view(), name="check_user_login"),
    path('email_verification/', views.CheckEmailView.as_view(), name="email_verification"),
    path('check_pwd/', views.CheckPwdView.as_view(), name="check_pwd"),
]
