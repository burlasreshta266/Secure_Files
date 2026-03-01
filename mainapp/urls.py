from . import views
from django.urls import path

urlpatterns = [
    path('', views.index, name='index'),
    path('enroll', views.enroll, name='enroll'),
    path('login', views.login, name='login'),
    path('logout', views.logout, name='logout'),
    path('home', views.home, name='home'),
    path('folders', views.folders, name='folders'),
    path('shared_folders', views.shared_folders, name='shared_folders'),
    path('folder/<int:folder_id>/', views.folder_detail, name='folder_detail'),
    path('join/<int:folder_id>/', views.join_folder, name='join_folder'),
    path('download/<int:file_id>/', views.download_file, name='download_file'),    
    path('my_files', views.my_files, name="my_files")
]