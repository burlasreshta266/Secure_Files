from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render, redirect
from .models import User, File, Folder
from django.contrib import messages
import json, os, base64
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from cryptography.hazmat.primitives import serialization
from .biometric.encode import encode_bins
from .biometric.fuzzy import fuzzy_gen, fuzzy_rep
from .biometric.keys import generate_authentication_key, generate_encryption_material
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .forms import FolderForm, FileUploadForm


WORD = 'securebiometricstorage'
W_LEN = len(WORD)
MIN_DWELL = 30
MAX_DWELL = 500
DWELL_RANGE = [110]
MIN_FLIGHT = 0
MAX_FLIGHT = 1000
FLIGHT_RANGE = [130]
MAX_THRESHOLD = 0.65*(2*W_LEN-1)


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

def get_user_key(request):
    s_hex = request.session.get('bio_key')
    if not s_hex:
        return None
    S = bytes.fromhex(s_hex)
    return generate_encryption_material(S)

def encrypt_data(key, data):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return base64.b64encode(nonce).decode('utf-8'), base64.b64encode(ciphertext).decode('utf-8')

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

    if not tim_1 or not biometric_1 or not tim_2 or not biometric_2:
        messages.error(request, 'Biometric must not be empty')
        return redirect('login')
        
    # check if user typed correct phrase
    if biometric_1!=WORD or biometric_2!=WORD:
        messages.error(request, 'Wrong biometric word typed')
        return redirect(enroll)

    # get and validate timestamps
    try:
        timestamps_1 = json.loads(tim_1)
        timestamps_2 = json.loads(tim_2)
    except:
        messages.error(request, 'timestamps not loaded correctly')
        return redirect('enroll')

    if not validate_timestamps(timestamps_1) or not validate_timestamps(timestamps_2):
        messages.error(request, 'Wrong biometric word typed')
        return redirect(enroll)

    timestamps_1 = sorted(timestamps_1, key = lambda x : x['dt'])
    timestamps_2 = sorted(timestamps_2, key = lambda x : x['dt'])

    # get and validate Dwell and Flight times
    times_1 = create_dwell_flight(timestamps_1)
    times_2 = create_dwell_flight(timestamps_2)
    if not validate_dwell_flight(times_1) or not validate_dwell_flight(times_2):
        messages.error(request, 'Invalid dwell and flight')
        return redirect(enroll)
        
    # Average the raw times
    averaged_times = []
    for i in range(len(times_1)):
        raw_avg = (times_1[i] + times_2[i]) / 2
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
    S, helper = fuzzy_gen(enroll_bits)

    # generate keys from S
    private_key, public_key = generate_authentication_key(S.encode('utf-8'))

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    helper_data = helper.encode('utf-8')

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
    helper_data_bytes = bytes(user.helper_data)

    helper_str = helper_data_bytes.decode('utf-8')

    print(f"Enroll Bins: {enroll_bins}")
    print(f"Login Bins:  {''.join(map(str, login_bins))}")
    
    diff_count = sum(1 for a, b in zip(enroll_bins, ''.join(map(str, login_bins))) if a != b)
    print(f"Number of differing bins: {diff_count}")

    recovered_S = fuzzy_rep(login_bits, helper_str)
    
    if not recovered_S:
        messages.error(request, 'Recovered S should not be none')
        return redirect('login')

    p, login_public_key = generate_authentication_key(recovered_S.encode('utf-8'))

    login_public_key_bytes = login_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # compare login and enroll public keys
    public_key = user.public_key_bytes
    if public_key==login_public_key_bytes:
        auth_login(request, user)
        request.session['bio_key'] = recovered_S.encode('utf-8').hex()
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
    recent_folders = Folder.objects.filter(creator=request.user).order_by('-folder_id')[:4]
    recent_files = File.objects.filter(uploaded_by=request.user).order_by('-file_id')[:5]
    
    return render(request, 'mainapp/home.html', {
        'recent_folders': recent_folders,
        'recent_files': recent_files
    })


@login_required
def folders(request):
    # 1. Handle Folder Creation
    if request.method == 'POST':
        form = FolderForm(request.POST)
        if form.is_valid():
            folder = form.save(commit=False)
            folder.creator = request.user
            folder.save()
            return redirect('folders')
    else:
        form = FolderForm()

    # 2. Get Lists
    my_folders = Folder.objects.filter(creator=request.user)

    return render(request, 'mainapp/folders.html', {
        'form': form,
        'my_folders': my_folders,
        
    })


@login_required
def shared_folders(request):
    shared_folders_list = request.user.shared_folders.all()
    return render(request, "mainapp/shared_folders.html", {
        'shared_folders': shared_folders_list
    })


@login_required
def folder_detail(request, folder_id):
    try:
        folder = Folder.objects.get(folder_id=folder_id)
    except Folder.DoesNotExist:
        messages.error(request, "Folder not found")
        return redirect('folders')

    # Check Permissions
    if folder.creator != request.user and request.user not in folder.shared_users.all():
        messages.error(request, "You do not have access to this folder")
        return redirect('folders')

    # Handle File Upload
    if request.method == 'POST':
        file_form = FileUploadForm(request.POST, request.FILES)
        if file_form.is_valid():
            uploaded_file = request.FILES['file']
            file_data = uploaded_file.read()
            
            # Encrypt
            key = get_user_key(request)
            if not key:
                messages.error(request, "Biometric session expired. Please login again.")
                return redirect('login')
                
            nonce_b64, ciphertext_b64 = encrypt_data(key, file_data)
            
            # Save
            File.objects.create(
                uploaded_by=request.user,
                filename=uploaded_file.name,
                folder=folder,
                ciphertext=ciphertext_b64,
                nonce=nonce_b64
            )
            messages.success(request, "File uploaded and encrypted!")
            return redirect('folder_detail', folder_id=folder_id)
    else:
        file_form = FileUploadForm()

    files = File.objects.filter(folder=folder)
    
    # Generate Invite Link (Simple version)
    invite_link = request.build_absolute_uri(f"/join/{folder.folder_id}/")

    return render(request, 'mainapp/folder_detail.html', {
        'folder': folder,
        'files': files,
        'file_form': file_form,
        'invite_link': invite_link
    })


@login_required
def join_folder(request, folder_id):
    try:
        folder = Folder.objects.get(folder_id=folder_id)
    except Folder.DoesNotExist:
        messages.error(request, "Folder does not exist")
        return redirect('folders')
        
    if folder.creator == request.user:
        messages.info(request, "You are the owner of this folder.")
        return redirect('folder_detail', folder_id=folder_id)

    # Add user to shared list
    folder.shared_users.add(request.user)
    messages.success(request, f"You have joined '{folder.foldername}'")
    return redirect('folder_detail', folder_id=folder_id)


@login_required
def download_file(request, file_id):
    file_obj = get_object_or_404(File, file_id=file_id)
    folder = file_obj.folder

    # Permission Check
    if folder and (folder.creator != request.user and request.user not in folder.shared_users.all()):
        return HttpResponse("Access Denied", status=403)
    
    key = get_user_key(request)
    if not key:
        messages.error(request, "Please login to decrypt files.")
        return redirect('login')

    try:
        # Decode DB fields
        nonce = base64.b64decode(file_obj.nonce)
        ciphertext = base64.b64decode(file_obj.ciphertext)
        
        # Decrypt
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Serve File
        response = HttpResponse(plaintext, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{file_obj.filename}"'
        return response
    except Exception as e:
        return HttpResponse(f"Decryption Failed: {str(e)}", status=500)


@login_required
def my_files(request):
    user_files = File.objects.filter(uploaded_by=request.user)
    return render(request, 'mainapp/my_files.html', {'files': user_files})