from django.shortcuts import render, redirect
from .models import User
from django.contrib import messages
import random, json
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from cryptography.hazmat.primitives import serialization
from .biometric.encode import encode_bins
from .biometric.fuzzy import fuzzy_extractor, validate_S
from .biometric.keys import generate_authentication_key


WORD = 'securefilesbiometriclogin'
W_LEN = len(WORD)
MIN_DWELL = 30
MAX_DWELL = 500
DWELL_RANGE = [60, 90, 120, 160]
MIN_FLIGHT = 0
MAX_FLIGHT = 1000
FLIGHT_RANGE = [30, 70, 120, 200]
MAX_THRESHOLD = 5


#---------------------
#   Helper Functions
#---------------------
def validate_timestamps(timestamps):
    if len(timestamps)!=W_LEN:
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
            if not (flight>=0 and flight<MAX_FLIGHT):
                res.clear()
                return res
            res.append(flight)
    return res

def validate_dwell_flight(times):
    if len(times)!=(2*W_LEN-1):
        return False
    return all(
        (t >= MIN_DWELL and t <= MAX_DWELL) if i % 2 == 0 else
        (t >= MIN_FLIGHT and t <= MAX_FLIGHT)
        for i, t in enumerate(times)
    )

def choose_dwell_bin(dt):
    for i, r in enumerate(DWELL_RANGE):
        if dt<=r:
            return i
    return len(DWELL_RANGE)

def choose_flight_bin(ft):
    for i, r in enumerate(FLIGHT_RANGE):
        if ft<=r:
            return i
    return len(FLIGHT_RANGE)

def create_bins(times):
    bins = []
    for i, t in enumerate(times):
        if i%2==0:
            bins.append(choose_dwell_bin(t))
        else:
            bins.append(choose_flight_bin(t))
    return bins

def validate_bins(bins, times):
    if len(bins)!=(2*W_LEN-1):
        return False
    if(len(bins)!=len(times)):
        return False
    for i, b in enumerate(bins):
        if b<0:
            return False
        if i%2==0 and b>len(DWELL_RANGE):
            return False
        if i%2!=0 and b>len(FLIGHT_RANGE):
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
    if request.method != 'POST':
        return render(request, 'mainapp/enroll.html')
    
    username = request.POST.get('username')
    biometric = request.POST.get('biometric')
    tim = request.POST.get('timestamps')
    
    # check if user typed correct phrase
    if biometric!=WORD:
        messages.error(request, 'Wrong biometric word typed')
        return redirect(enroll)

    # get and validate timestamps
    timestamps = json.loads(tim)
    if not validate_timestamps(timestamps):
        messages.error(request, 'Wrong biometric word typed')
        return redirect(enroll)

    timestamps = sorted(timestamps, key = lambda x : x['dt'])

    # get and validate Dwell and Flight times
    times = create_dwell_flight(timestamps)
    if not validate_dwell_flight(times):
        messages.error(request, 'Invalid biometric')
        return redirect(enroll)
        
    # create bins 
    bins = create_bins(times)
    if not validate_bins(bins, times):
        messages.error(request, 'Invalid biometric')
        return redirect(enroll)
    # store bins for threshold validation during login
    enroll_bins = ''.join(list(map(str, bins)))
        
    # generate bits, S, helper_data, keys
    bits = encode_bins(bins)
    S, helper_data = fuzzy_extractor(bits)
    private_key, public_key = generate_authentication_key(S)

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Create the user
    User.objects.create_user(
        username=username, 
        password=None,
        helper_data=helper_data,
        public_key_bytes=public_key_bytes,
        enroll_bins=enroll_bins )
        
    messages.success(request, 'Enrollment successful! You can now log in.')
    return redirect('login')


# User login
def login(request): 
    if request.method != 'POST':
        return render(request, 'mainapp/login.html')
    
    username = request.POST.get('username')
    biometric = request.POST.get('biometric')
    tim = request.POST.get('timestamps')
    
    # check if user typed correct phrase
    if biometric!=WORD:
        messages.error(request, 'Wrong biometric word typed')
        return redirect('login')

    # get and validate timestamps
    timestamps = json.loads(tim)
    if not validate_timestamps(timestamps):
        messages.error(request, 'Wrong biometric word typed')
        return redirect('login')

    timestamps = sorted(timestamps, key = lambda x : x['dt'])

    # get and validate Dwell and Flight times
    times = create_dwell_flight(timestamps)
    if not validate_dwell_flight(times):
        messages.error(request, 'Invalid biometric')
        return redirect('login')
        
    # create bins 
    login_bins = create_bins(times)
    if not validate_bins(login_bins, times):
        messages.error(request, 'Invalid biometric')
        return redirect('login')

    # check if user exists
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        messages.error(request, "Username does not exist")
        return redirect('login')
    
    # compare enroll and login bins
    enroll_bins = user.enroll_bins
    # length
    if len(enroll_bins)!=len(login_bins):
        messages.error(request, 'Invalid biometric')
        return redirect('login')
    # threshold
    threshold = 0
    for i in range(len(login_bins)):
        t = abs(int(enroll_bins[i])-int(login_bins[i]))
        threshold+=t
    if threshold>MAX_THRESHOLD:
        messages.error(request, 'Invalid biometric')
        return redirect('login')
        
    bits = encode_bins(login_bins)
    helper_data = user.helper_data
    public_key_bytes = user.public_key_bytes

    if len(bits)!=len(helper_data):
        messages.error(request, 'Invalid biometric')
        return redirect('login')
    
    # create S from login data
    S_list = [str(int(bits[i])^int(helper_data[i])) for i in range(len(bits))]
    S1 = ''.join(S_list)
    if(not validate_S(S1)):
        messages.error(request, 'Invalid biometric')
        return redirect('login')
    
    # generate keys from login S
    p, generated_public_key = generate_authentication_key(S1)
    generated_public_key_bytes = generated_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # if both enroll and login keys match, the user logged in
    if generated_public_key_bytes==public_key_bytes:
        auth_login(request, user)
        return redirect('home')
    else:
        messages.error(request, 'Invalid biometric')
        return redirect('login')
    


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
