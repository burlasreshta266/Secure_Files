from . import views
from django.urls import path

urlpatterns = [
    path('', views.index, name='index'),
    path('enroll', views.enroll, name='enroll'),
    path('login', views.login, name='login'),
    path('logout', views.logout, name='logout'),
    path('home', views.home, name='home'),
    path('files', views.files, name='files'),
    path('folders', views.folders, name='folders'),
]