from django.urls import path

from . import views

urlpatterns = [
   
    path('sm2compare/', views.compare, name='sm2compare'),
    path('sm2sign/', views.sign, name='sm2sign'),
    path('sm2exchange/', views.exchange, name='sm2exchange'),
    path('ecc/', views.ecc, name='ecc'),
    path('security/', views.security, name='security'),

    

]