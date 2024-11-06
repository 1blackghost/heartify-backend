from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('predict/', views.predict_heart_disease_view, name='predict'),
    path('getResults/', views.get_results_view, name='getResults'), 
    path('save-heart-condition/', views.save_heart_condition, name='save_heart_condition'),
    path('get-heart-condition/', views.get_heart_condition, name='get_heart_condition'),
]
