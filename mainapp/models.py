from django.db import models
from django.contrib.auth.models import AbstractUser

# Custom User model extending AbstractUser
class User(AbstractUser):
    enroll_bins = models.TextField()
    helper_data = models.BinaryField()
    public_key_bytes = models.BinaryField ()
    role = models.CharField(max_length=50, default="viewer")

    def __str__(self):
        return self.username


# Folder model to store folder information
class Folder(models.Model):
    folder_id = models.AutoField(primary_key=True)
    creator = models.ForeignKey(User, related_name='created_folders', on_delete=models.CASCADE)
    foldername = models.CharField(max_length=255)
    shared_users = models.ManyToManyField(User, related_name='shared_folders', blank=True)

    def __str__(self):
        return self.foldername
    

# File model to store file information
class File(models.Model):
    file_id = models.AutoField(primary_key=True)
    uploaded_by = models.ForeignKey(User, related_name='uploaded_files', on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    folder = models.ForeignKey('Folder', related_name='contains_files', on_delete=models.CASCADE, null=True, blank=True)
    ciphertext = models.TextField()
    nonce = models.TextField()

    def __str__(self):
        return self.filename
    