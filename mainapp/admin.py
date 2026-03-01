from django.contrib import admin
from .models import User, Folder, File

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'role')
    search_fields = ('username', 'email')

@admin.register(Folder)
class FolderAdmin(admin.ModelAdmin):
    list_display = ('foldername', 'creator')
    search_fields = ('foldername', 'creator__username')

@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ('filename', 'uploaded_by', 'folder')
    search_fields = ('filename', 'uploaded_by__username', 'folder__foldername')