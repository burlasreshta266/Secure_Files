from django.shortcuts import render

# Welcome page view
def index(request):
    return render(request, 'mainapp/welcome.html')


# Enroll new user
def enroll(request):
    return render(request, 'mainapp/enroll.html')


# User login
def login(request): 
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
