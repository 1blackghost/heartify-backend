from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),

    path('save-heart-condition/', views.save_heart_condition, name='save_heart_condition'),
    path('get-heart-condition/', views.get_heart_condition, name='get_heart_condition'),
]
