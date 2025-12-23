from math import ceil
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

MIN_BITS = 128

def normalize_s(S):
    if len(S)<MIN_BITS:
        raise ValueError("length of bits must be longer")
    for i in S:
        if i!='0' and i!='1':
            raise ValueError("bits must contain only 1 or 0")
    l = ceil(len(S)/8)
    return int(S, 2).to_bytes(l, byteorder='big')


def generate_authentication_key(S):
    secret_bytes = normalize_s(S)
    info = 'authetication'.encode()
    hkdf = HKDF(
        algorithm = hashes.SHA256, 
        length = 32,
        info = info)
    key_material = hkdf.derive(secret_bytes)
    private_key = X25519PrivateKey.from_private_bytes(key_material)
    public_key = private_key.public_key()

    return private_key, public_key


def generate_encryption_material(S):
    secret_bytes = normalize_s(S)
    info = 'file-encryption'.encode()
    hkdf = HKDF(
        algorithm = hashes.SHA256, 
        length = 32,
        info = info)
    key_material = hkdf.derive(secret_bytes)
    return key_material


def generate_all_keys(S):
    private_key, public_key = generate_authentication_key(S)
    enc_material = generate_encryption_material(S)
    return private_key, public_key, enc_material