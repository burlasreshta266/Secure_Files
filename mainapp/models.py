from django.db import models
from django.contrib.auth.models import AbstractUser

# Custom User model extending AbstractUser
class User(AbstractUser):
    enroll_bins = models.TextField()
    helper_data = models.TextField()
    public_key_bytes = models.TextField()
    role = models.CharField(max_length=50, default="viewer")

    def __str__(self):
        return self.username


# Folder model to store folder information
class Folder(models.Model):
    folder_id = models.AutoField(primary_key=True)
    creator = models.ForeignKey(User, on_delete=models.CASCADE)
    foldername = models.CharField(max_length=255)

    def __str__(self):
        return self.foldername
    

# File model to store file information
class File(models.Model):
    file_id = models.AutoField(primary_key=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    folder = models.ForeignKey('Folder', on_delete=models.CASCADE, null=True, blank=True)
    ciphertext = models.TextField()

    def __str__(self):
        return self.filename
    