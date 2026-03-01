from datetime import timedelta
import base64
import json
import os
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .biometric.encode import encode_bins
from .biometric.fuzzy import fuzzy_gen, fuzzy_rep
from .biometric.keys import generate_authentication_key, generate_encryption_material
from .forms import FileUploadForm, FolderForm
from .models import File, Folder, User


DEFAULT_WORD = 'securefiles2026'
MIN_DWELL = 30
MAX_DWELL = 500
DWELL_RANGE = [110]
MIN_FLIGHT = 0
MAX_FLIGHT = 1000
FLIGHT_RANGE = [130]
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15


# ---------------------
#   Helper Functions
# ---------------------
def validate_timestamps(timestamps, expected_length):
    if len(timestamps) != expected_length:
        return False
    for char in timestamps:
        if 'key' not in char or 'dt' not in char or 'ut' not in char:
            return False
        if char['dt'] >= char['ut']:
            return False
    return True


def create_dwell_flight(timestamps):
    res = []
    for i in range(len(timestamps)):
        char = timestamps[i]
        dwell = char['ut'] - char['dt']
        res.append(dwell)
        if i < len(timestamps) - 1:
            flight = timestamps[i + 1]['dt'] - char['ut']
            if not (0 <= flight < MAX_FLIGHT):
                return []
            res.append(flight)
    return res


def validate_dwell_flight(times, expected_length):
    if len(times) != (2 * expected_length - 1):
        return False
    return all(
        (MIN_DWELL <= t <= MAX_DWELL) if i % 2 == 0 else (MIN_FLIGHT <= t <= MAX_FLIGHT)
        for i, t in enumerate(times)
    )


def choose_dwell_bin(dt):
    for i, r in enumerate(DWELL_RANGE):
        if dt <= r:
            return i
    return len(DWELL_RANGE)


def choose_flight_bin(ft):
    for i, r in enumerate(FLIGHT_RANGE):
        if ft <= r:
            return i
    return len(FLIGHT_RANGE)


def create_bins(times):
    bins = []
    for i, t in enumerate(times):
        bins.append(choose_dwell_bin(t) if i % 2 == 0 else choose_flight_bin(t))
    return bins


def validate_bins(bins, times):
    if len(bins) != len(times):
        return False
    for i, b in enumerate(bins):
        if b < 0:
            return False
        if i % 2 == 0 and b > len(DWELL_RANGE):
            return False
        if i % 2 != 0 and b > len(FLIGHT_RANGE):
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


def detect_pii(text_data):
    pii_patterns = {
        'Email Address': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'Credit Card': r'\b(?:\d[ -]*?){13,16}\b',
        'SSN/ID Number': r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b',
        'Phone Number': r'\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b',
    }

    found_pii = []
    for pii_type, pattern in pii_patterns.items():
        if re.search(pattern, text_data):
            found_pii.append(pii_type)

    return found_pii


def _record_failed_login(user):
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= MAX_FAILED_LOGINS:
        user.lockout_until = timezone.now() + timedelta(minutes=LOCKOUT_MINUTES)
    user.save(update_fields=['failed_login_attempts', 'lockout_until'])


def _reset_failed_login(user):
    user.failed_login_attempts = 0
    user.lockout_until = None
    user.save(update_fields=['failed_login_attempts', 'lockout_until'])


def _is_locked_out(user):
    return bool(user.lockout_until and user.lockout_until > timezone.now())


# ---------------------
#   Page Views
# ---------------------
def index(request):
    return render(request, 'mainapp/welcome.html')


def enroll(request):
    if request.method != 'POST':
        return render(request, 'mainapp/enroll.html', {'bio_word': DEFAULT_WORD})

    username = request.POST.get('username')
    password = request.POST.get('password')
    biometric_phrase = request.POST.get('biometric_phrase') or DEFAULT_WORD
    biometric_1 = request.POST.get('biometric_1')
    tim_1 = request.POST.get('timestamps_1')
    biometric_2 = request.POST.get('biometric_2')
    tim_2 = request.POST.get('timestamps_2')

    if not username or not password:
        messages.error(request, 'Username and password are required')
        return redirect('enroll')

    if not tim_1 or not biometric_1 or not tim_2 or not biometric_2:
        messages.error(request, 'Biometric must not be empty')
        return redirect('enroll')

    if biometric_1 != biometric_phrase or biometric_2 != biometric_phrase:
        messages.error(request, 'Wrong biometric word typed')
        return redirect('enroll')

    try:
        timestamps_1 = json.loads(tim_1)
        timestamps_2 = json.loads(tim_2)
    except json.JSONDecodeError:
        messages.error(request, 'timestamps not loaded correctly')
        return redirect('enroll')

    phrase_length = len(biometric_phrase)
    if not validate_timestamps(timestamps_1, phrase_length) or not validate_timestamps(timestamps_2, phrase_length):
        messages.error(request, 'Wrong biometric word typed')
        return redirect('enroll')

    timestamps_1 = sorted(timestamps_1, key=lambda x: x['dt'])
    timestamps_2 = sorted(timestamps_2, key=lambda x: x['dt'])

    times_1 = create_dwell_flight(timestamps_1)
    times_2 = create_dwell_flight(timestamps_2)
    if not validate_dwell_flight(times_1, phrase_length) or not validate_dwell_flight(times_2, phrase_length):
        messages.error(request, 'Invalid dwell and flight')
        return redirect('enroll')

    averaged_times = [(times_1[i] + times_2[i]) / 2 for i in range(len(times_1))]
    bins = create_bins(averaged_times)

    if not validate_bins(bins, averaged_times):
        messages.error(request, 'Invalid bins generated from average')
        return redirect('enroll')

    enroll_bins = ''.join(list(map(str, bins)))
    enroll_bits = encode_bins(bins)
    S, helper = fuzzy_gen(enroll_bits)

    private_key, public_key = generate_authentication_key(S.encode('utf-8'))
    _ = private_key

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    helper_data = helper.encode('utf-8')

    if User.objects.filter(username=username).exists():
        messages.error(request, 'Username already exists')
        return redirect('enroll')

    User.objects.create_user(
        username=username,
        password=password,
        biometric_phrase=biometric_phrase,
        biometric_secret=biometric_phrase,
        helper_data=helper_data,
        public_key_bytes=public_key_bytes,
        enroll_bins=enroll_bins,
    )

    messages.success(request, 'Enrollment successful! You can now log in.')
    return redirect('login')


def login(request):
    if request.method != 'POST':
        return render(request, 'mainapp/login.html', {'bio_word': DEFAULT_WORD})

    username = request.POST.get('username')
    user = User.objects.filter(username=username).first()
    if not user:
        messages.error(request, 'Username does not exist')
        return redirect('login')

    if _is_locked_out(user):
        messages.error(request, 'Too many failed attempts. Account temporarily locked.')
        return redirect('login')

    password = request.POST.get('password')
    if password and user.check_password(password):
        _reset_failed_login(user)
        auth_login(request, user)
        request.session['bio_key'] = user.biometric_secret.encode('utf-8').hex()
        request.session['login_threshold'] = 0
        messages.success(request, 'Logged in using password recovery flow.')
        return redirect('home')

    biometric = request.POST.get('biometric')
    tim = request.POST.get('timestamps')

    if not tim or not biometric:
        _record_failed_login(user)
        messages.error(request, 'Biometric must not be empty')
        return redirect('login')

    if len(tim) <= 0 or len(biometric) <= 0:
        _record_failed_login(user)
        messages.error(request, 'Biometric must not be empty')
        return redirect('login')

    expected_phrase = user.biometric_phrase
    if biometric != expected_phrase:
        _record_failed_login(user)
        messages.error(request, 'Wrong biometric word typed')
        return redirect('login')

    try:
        timestamps = json.loads(tim)
    except json.JSONDecodeError:
        _record_failed_login(user)
        messages.error(request, 'timestamps not loaded correctly')
        return redirect('login')

    if not validate_timestamps(timestamps, len(expected_phrase)):
        _record_failed_login(user)
        messages.error(request, 'Wrong biometric word typed')
        return redirect('login')

    timestamps = sorted(timestamps, key=lambda x: x['dt'])

    times = create_dwell_flight(timestamps)
    if not validate_dwell_flight(times, len(expected_phrase)):
        _record_failed_login(user)
        messages.error(request, 'Invalid dwell and flight')
        return redirect('login')

    login_bins = create_bins(times)
    if not validate_bins(login_bins, times):
        _record_failed_login(user)
        messages.error(request, 'Invalid bins')
        return redirect('login')

    enroll_bins = user.enroll_bins
    if len(enroll_bins) != len(login_bins):
        _record_failed_login(user)
        messages.error(request, 'Invalid enroll bins does not match login bins')
        return redirect('login')

    threshold = 0
    for i in range(len(login_bins)):
        threshold += abs(int(enroll_bins[i]) - int(login_bins[i]))

    max_threshold = 0.65 * (2 * len(expected_phrase) - 1)
    if threshold > max_threshold:
        _record_failed_login(user)
        messages.error(request, 'Threshold exceed')
        return redirect('login')

    login_bits = encode_bins(login_bins)
    helper_str = bytes(user.helper_data).decode('utf-8')
    recovered_S = fuzzy_rep(login_bits, helper_str)

    if not recovered_S:
        _record_failed_login(user)
        messages.error(request, 'Recovered S should not be none')
        return redirect('login')

    _, login_public_key = generate_authentication_key(recovered_S.encode('utf-8'))
    login_public_key_bytes = login_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    if user.public_key_bytes == login_public_key_bytes:
        _reset_failed_login(user)
        auth_login(request, user)
        request.session['bio_key'] = recovered_S.encode('utf-8').hex()
        request.session['login_threshold'] = threshold
        return redirect('home')

    _record_failed_login(user)
    messages.error(request, 'Invalid User')
    return redirect('login')


@login_required
def logout(request):
    auth_logout(request)
    return redirect('login')


@login_required
def home(request):
    recent_folders = Folder.objects.filter(creator=request.user).order_by('-folder_id')[:4]
    recent_files = File.objects.filter(uploaded_by=request.user).order_by('-file_id')[:5]

    login_threshold = request.session.get('login_threshold', 0)
    expected_phrase_length = len(request.user.biometric_phrase)
    max_threshold = 0.65 * (2 * expected_phrase_length - 1)

    health_percentage = max(0, int(((max_threshold - login_threshold) / max_threshold) * 100))

    security_status = 'Excellent'
    if health_percentage < 50:
        security_status = 'Critical'
    elif health_percentage < 80:
        security_status = 'Fair'

    insights = []
    if health_percentage < 85:
        insights.append('Your typing rhythm has changed slightly. Ensure you are using a consistent keyboard.')

    if not request.user.has_usable_password():
        insights.append('Biometric-only mode is active. Your files are protected by your typing signature.')

    return render(
        request,
        'mainapp/home.html',
        {
            'recent_folders': recent_folders,
            'recent_files': recent_files,
            'health_percentage': health_percentage,
            'security_status': security_status,
            'insights': insights,
        },
    )


@login_required
def folders(request):
    if request.method == 'POST':
        form = FolderForm(request.POST)
        if form.is_valid():
            folder = form.save(commit=False)
            folder.creator = request.user
            folder.save()
            return redirect('folders')
    else:
        form = FolderForm()

    my_folders = Folder.objects.filter(creator=request.user)

    return render(request, 'mainapp/folders.html', {'form': form, 'my_folders': my_folders})


@login_required
def shared_folders(request):
    shared_folders_list = request.user.shared_folders.all()
    return render(request, 'mainapp/shared_folders.html', {'shared_folders': shared_folders_list})


@login_required
def folder_detail(request, folder_id):
    try:
        folder = Folder.objects.get(folder_id=folder_id)
    except Folder.DoesNotExist:
        messages.error(request, 'Folder not found')
        return redirect('folders')

    if folder.creator != request.user and request.user not in folder.shared_users.all():
        messages.error(request, 'You do not have access to this folder')
        return redirect('folders')

    if request.method == 'POST':
        file_form = FileUploadForm(request.POST, request.FILES)
        if file_form.is_valid():
            uploaded_file = request.FILES['file']
            file_data = uploaded_file.read()

            try:
                text_content = file_data.decode('utf-8')
                detected_items = detect_pii(text_content)

                if detected_items:
                    warning_msg = (
                        f"AI Security Warning: We detected sensitive information ({', '.join(detected_items)}) "
                        f"in '{uploaded_file.name}'. This file will be encrypted for your safety."
                    )
                    messages.warning(request, warning_msg)
            except UnicodeDecodeError:
                pass

            key = get_user_key(request)
            if not key:
                messages.error(request, 'Biometric session expired. Please login again.')
                return redirect('login')

            nonce_b64, ciphertext_b64 = encrypt_data(key, file_data)

            File.objects.create(
                uploaded_by=request.user,
                filename=uploaded_file.name,
                folder=folder,
                ciphertext=ciphertext_b64,
                nonce=nonce_b64,
            )
            messages.success(request, 'File uploaded and encrypted!')
            return redirect('folder_detail', folder_id=folder_id)
    else:
        file_form = FileUploadForm()

    files = File.objects.filter(folder=folder)
    invite_link = request.build_absolute_uri(f'/join/{folder.folder_id}/')

    return render(
        request,
        'mainapp/folder_detail.html',
        {'folder': folder, 'files': files, 'file_form': file_form, 'invite_link': invite_link},
    )


@login_required
def join_folder(request, folder_id):
    try:
        folder = Folder.objects.get(folder_id=folder_id)
    except Folder.DoesNotExist:
        messages.error(request, 'Folder does not exist')
        return redirect('folders')

    if folder.creator == request.user:
        messages.info(request, 'You are the owner of this folder.')
        return redirect('folder_detail', folder_id=folder_id)

    folder.shared_users.add(request.user)
    messages.success(request, f"You have joined '{folder.foldername}'")
    return redirect('folder_detail', folder_id=folder_id)


@login_required
def download_file(request, file_id):
    file_obj = get_object_or_404(File, file_id=file_id)
    folder = file_obj.folder

    if folder and (folder.creator != request.user and request.user not in folder.shared_users.all()):
        return HttpResponse('Access Denied', status=403)

    key = get_user_key(request)
    if not key:
        messages.error(request, 'Please login to decrypt files.')
        return redirect('login')

    try:
        nonce = base64.b64decode(file_obj.nonce)
        ciphertext = base64.b64decode(file_obj.ciphertext)

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        response = HttpResponse(plaintext, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{file_obj.filename}"'
        return response
    except Exception as e:
        return HttpResponse(f'Decryption Failed: {str(e)}', status=500)


@login_required
def my_files(request):
    files = File.objects.filter(uploaded_by=request.user)
    return render(request, 'mainapp/my_files.html', {'files': files})
