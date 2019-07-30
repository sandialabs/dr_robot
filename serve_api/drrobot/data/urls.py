from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('<str:domain_name>/', views.domain, name='domain')
]
