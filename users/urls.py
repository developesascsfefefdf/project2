from django.contrib.auth import views as auth_views
from django.urls import path

from users import views
from .views import CustomPasswordResetView
from .views import (
    UserListView,
    UserCreateView,
    UserUpdateView,
    UserDeleteView,
    UserRegistrationView,
    UserProfile,
    InviteUserView,  
)
from .views import (
    CustomPasswordResetView, 
    CustomPasswordResetConfirmView, 
    CustomLogoutView, 
    UserRegistrationView, 
    UserListView, 
    UserCreateView, 
    UserUpdateView, 
    UserDeleteView, 
    UserProfile, 
    home, 
    InviteUserView
)
from django.contrib.auth.views import LoginView, LogoutView


app_name = 'user_app'
urlpatterns = [
    path('', views.home, name='home'),
        path('user/invite/', views.InviteUserView.as_view(template_name='users/invite.html'), name='invite'),
    path('user/list/a/', views.UserListView.as_view(), name='list'),
    path('user/create/a/', views.UserCreateView.as_view(), name='create'),
    path('user/update/<int:pk>/a/', views.UserUpdateView.as_view(), name='update'),
    path('user/delete/<int:pk>/a/', views.UserDeleteView.as_view(), name='delete'),
     path('user/register/c/', UserRegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(template_name='users/login.html'), name='login'),
    path('user/profile/<int:pk>/c/', views.UserProfile.as_view(), name='profile'),
    path('logout/', auth_views.LogoutView.as_view(next_page='user_app:home'), name='logout'),

        path('password_reset/', CustomPasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='users/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='users/password_reset_complete.html'), name='password_reset_complete'),
]
