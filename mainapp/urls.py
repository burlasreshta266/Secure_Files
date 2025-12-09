from . import views
from django.urls import path

urls = [
    path('', views.index, name='index'),
    
]