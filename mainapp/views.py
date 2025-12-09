from django.shortcuts import render, redirect
from .models import User
from django.contrib import messages
import random

# Welcome page view
def index(request):
    return render(request, 'mainapp/welcome.html')


# Enroll new user
def enroll(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        biometric = request.POST.get('biometric')

        if not username or not biometric:
            messages.error(request, 'Please provide both username and biometric data.')
            return render(request, 'mainapp/enroll.html')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists. Please choose a different one.')
            return render(request, 'mainapp/enroll.html')
        
        helper_data = "fake_helper"+random.getrandbits(16)
        public_key = "fake_public"+random.getrandbits(16)

        user = User.objects.create(
            username=username, 
            biometric_data=biometric,
            helper_data=helper_data,
            public_key=public_key )
        
        messages.success(request, 'Enrollment successful! You can now log in.')
        return redirect('login')

    else: 
        return render(request, 'mainapp/enroll.html')


# User login
def login(request): 
    if request.method == 'POST':
        username = request.POST.get('username')
        biometric = request.POST.get('biometric')

        if not username or not biometric:
            messages.error(request, 'Please provide both username and biometric data.')
            return render(request, 'mainapp/login.html')
        try:
            user = User.objects.get(username=username) 
        except User.DoesNotExist:
            messages.error(request, 'Invalid username.')
            return render(request, 'mainapp/login.html')
        if user.biometric_data != biometric:
            messages.error(request, 'Biometric authentication failed.')
            return render(request, 'mainapp/login.html')
        
        token = "fake_token_"+random.getrandbits(16)
        request.session['user_id'] = user.id
        request.session['token'] = token

        return redirect('home')
    
    else:
        return render(request, 'mainapp/login.html')


# User logout
def logout(request):
    pass


# Home page view
def home(request):
    pass


# Files management view
def files(request):     
    pass


# Folders management view
def folders(request):
    pass
