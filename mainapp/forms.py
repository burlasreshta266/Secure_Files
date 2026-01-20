# mainapp/forms.py
from django import forms
from .models import Folder

class FolderForm(forms.ModelForm):
    class Meta:
        model = Folder
        fields = ['foldername']
        widgets = {
            'foldername': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter folder name'})
        }

class FileUploadForm(forms.Form):
    file = forms.FileField(widget=forms.ClearableFileInput(attrs={'class': 'form-control'}))