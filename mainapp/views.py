from django.shortcuts import render, redirect
from .models import User
from django.contrib import messages
import random, json
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from cryptography.hazmat.primitives import serialization
from .biometric.encode import encode_bins
from .biometric.fuzzy import generate_S, recover_S
from .biometric.keys import generate_authentication_key


WORD = 'securebiometricstorage'
W_LEN = len(WORD)
MIN_DWELL = 30
MAX_DWELL = 500
DWELL_RANGE = [110]
MIN_FLIGHT = 0
MAX_FLIGHT = 1000
FLIGHT_RANGE = [130]
MAX_THRESHOLD = 0.65*(2*W_LEN-1)

#  19 17 20 15 17 12 14 18 23 28 17 20 23 

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
        return render(request, 'mainapp/enroll.html', {
            'bio_word' : WORD
        })
    
    username = request.POST.get('username')
    biometric_1 = request.POST.get('biometric_1')
    tim_1 = request.POST.get('timestamps_1')
    biometric_2 = request.POST.get('biometric_2')
    tim_2 = request.POST.get('timestamps_2')
    biometric_3 = request.POST.get('biometric_3')
    tim_3 = request.POST.get('timestamps_3')

    if not tim_1 or not biometric_1 or not tim_2 or not biometric_2 or not tim_3 or not biometric_3:
        messages.error(request, 'Biometric must not be empty')
        return redirect('login')
        
    # check if user typed correct phrase
    if biometric_1!=WORD or biometric_2!=WORD or biometric_3!=WORD:
        messages.error(request, 'Wrong biometric word typed')
        return redirect(enroll)

    # get and validate timestamps
    try:
        timestamps_1 = json.loads(tim_1)
        timestamps_2 = json.loads(tim_2)
        timestamps_3 = json.loads(tim_3)
    except:
        messages.error(request, 'timestamps not loaded correctly')
        return redirect('enroll')

    if not validate_timestamps(timestamps_1) or not validate_timestamps(timestamps_2) or not validate_timestamps(timestamps_3):
        messages.error(request, 'Wrong biometric word typed')
        return redirect(enroll)

    timestamps_1 = sorted(timestamps_1, key = lambda x : x['dt'])
    timestamps_2 = sorted(timestamps_2, key = lambda x : x['dt'])
    timestamps_3 = sorted(timestamps_3, key = lambda x : x['dt'])

    # get and validate Dwell and Flight times
    times_1 = create_dwell_flight(timestamps_1)
    times_2 = create_dwell_flight(timestamps_2)
    times_3 = create_dwell_flight(timestamps_3)
    if not validate_dwell_flight(times_1) or not validate_dwell_flight(times_2) or not validate_dwell_flight(times_3):
        messages.error(request, 'Invalid dwell and flight')
        return redirect(enroll)
        
    # Average the raw times
    averaged_times = []
    for i in range(len(times_1)):
        raw_avg = (times_1[i] + times_2[i] + times_3[i]) / 3
        averaged_times.append(raw_avg)

    # Create bins
    bins = create_bins(averaged_times)

    if not validate_bins(bins, averaged_times):
        messages.error(request, 'Invalid bins generated from average')
        return redirect(enroll)

    # store bins for threshold validation during login
    enroll_bins = ''.join(list(map(str, bins)))
    
    # get bits from bins
    enroll_bits = encode_bins(bins)

    # get S and helper data
    S, helper_data = generate_S(enroll_bits)

    # generate keys from S
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
        return render(request, 'mainapp/login.html', {
            'bio_word' : WORD
        })
    
    username = request.POST.get('username')
    biometric = request.POST.get('biometric')
    tim = request.POST.get('timestamps')

    if not tim or not biometric:
        messages.error(request, 'Biometric must not be empty')
        return redirect('login')
    
    if len(tim)<=0 or len(biometric)<=0:
        messages.error(request, 'Biometric must not be empty')
        return redirect('login')
    
    # check if user typed correct phrase
    if biometric!=WORD:
        messages.error(request, 'Wrong biometric word typed')
        return redirect('login')

    # get and validate timestamps
    try:
        timestamps = json.loads(tim)
    except:
        messages.error(request, 'timestamps not loaded correctly')
        return redirect('login')
    
    if not validate_timestamps(timestamps):
        messages.error(request, 'Wrong biometric word typed')
        return redirect('login')

    timestamps = sorted(timestamps, key = lambda x : x['dt'])

    # get and validate Dwell and Flight times
    times = create_dwell_flight(timestamps)
    if not validate_dwell_flight(times):
        messages.error(request, 'Invalid dwell and flight')
        return redirect('login')
        
    # create bins 
    login_bins = create_bins(times)
    if not validate_bins(login_bins, times):
        messages.error(request, 'Invalid bins')
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
        messages.error(request, 'Invalid enroll bins does not match login bins')
        return redirect('login')
    # threshold
    threshold = 0
    for i in range(len(login_bins)):
        t = abs(int(enroll_bins[i])-int(login_bins[i]))
        threshold+=t
    if threshold>MAX_THRESHOLD:
        messages.error(request, 'Threshold exceed')
        return redirect('login')
        
    # get bits rom bins
    login_bits = encode_bins(login_bins)

    # get helper data from database
    helper_data = bytes(user.helper_data)

    print(f"Enroll Bins: {enroll_bins}")
    print(f"Login Bins:  {''.join(map(str, login_bins))}")
    
    # Calculate difference manually to see it
    diff_count = sum(1 for a, b in zip(enroll_bins, ''.join(map(str, login_bins))) if a != b)
    print(f"Number of differing bins: {diff_count}")

    # recover S
    recovered_S = recover_S(login_bits, helper_data)
    if not recovered_S:
        messages.error(request, 'Recovered S should not be none')
        return redirect('login')

    # generate keys from recovered S
    p, login_public_key = generate_authentication_key(recovered_S)

    login_public_key_bytes = login_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # compare login and enroll public keys
    public_key = user.public_key_bytes
    if public_key==login_public_key_bytes:
        auth_login(request, user)
        return redirect('home')
    else:
        messages.error(request, 'Invaid User')
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
