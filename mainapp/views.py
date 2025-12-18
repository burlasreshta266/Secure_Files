from django.shortcuts import render, redirect
from .models import User
from django.contrib import messages
import random
import json
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required

WORD = 'securefiles'
W_LEN = len(WORD)
MIN_DWELL = 30
MAX_DWELL = 500
MIN_FLIGHT = 0
MAX_FLIGHT = 1000


#---------------------
#   Helper Functions
#---------------------
def validate_timestamps(timestamps):
    if len(timestamps)<2:
        return False
    for char in timestamps:
        if 'key' not in char or 'dt' not in char or 'ut' not in char:
            return False
        if char['dt']>=char['ut']:
            return False
    return True

def create_dwell_flight(timestamps):
    res = []
    for i in range(len(timestamps)):
        char = timestamps[i]
        dwell = char['ut']-char['dt']
        res.append(dwell)
        if(i<len(timestamps)-1):
            flight = timestamps[i+1]['dt'] - char['ut']
            if flight>=0 and flight<MAX_FLIGHT:
                res.append(flight)
    return res

def validate_dwell_flight(times):
    if len(times)<3:
        return False
    for d in range(0, len(times), 2):
        if times[d] < MIN_DWELL or times[d] > MAX_DWELL:
            return False
    for f in range(1, len(times), 2):
        if times[f] < MIN_FLIGHT or times[f] > MAX_FLIGHT:
            return False
    return True


#---------------------
#   Page Views
#---------------------

# Welcome page view
def index(request):
    return render(request, 'mainapp/welcome.html')


# Enroll new user
def enroll(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        biometric = request.POST.get('biometric')
        tim = request.POST.get('timestamps')
        
        timestamps = json.loads(tim)
        if not validate_timestamps(timestamps):
            messages.error(request, 'Invalid biometric word.')
            return redirect(enroll)

        timestamps = sorted(timestamps, key = lambda x : x['dt'])

        times = create_dwell_flight(timestamps)
        if not validate_dwell_flight(times):
            messages.error(request, 'Invalid biometric word.')
            return redirect(enroll)


        if not username or not biometric:
            messages.error(request, 'Please provide both username and biometric data.')
            return render(request, 'mainapp/enroll.html')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists. Please choose a different one.')
            return render(request, 'mainapp/enroll.html')
        
        helper_data = "fake_helper"+str(random.getrandbits(16))
        public_key = "fake_public"+str(random.getrandbits(16))

        User.objects.create_user(
            username=username, 
            password=None,
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
        
        auth_login(request, user)
        
        return redirect('home')
    
    else:
        return render(request, 'mainapp/login.html')


# User logout
@login_required
def logout(request):
    auth_logout(request)
    return redirect('login')


# Home page view
@login_required
def home(request):
    return render(request, 'mainapp/home.html')


# Files management view
@login_required
def files(request):     
    pass


# Folders management view
@login_required
def folders(request):
    pass
