from math import ceil
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

MIN_BYTES = 6

def generate_authentication_key(S):
    if not isinstance(S, (bytes, bytearray)):
        raise TypeError("Secret S must be bytes")
    if len(S)<MIN_BYTES:
        raise ValueError('S must be longer')
    info = 'authentication'.encode()
    hkdf = HKDF(
        algorithm = hashes.SHA256(), 
        length = 32,
        info = info)
    key_material = hkdf.derive(S)
    private_key = X25519PrivateKey.from_private_bytes(key_material)
    public_key = private_key.public_key()

    return private_key, public_key


def generate_encryption_material(S):
    if not isinstance(S, (bytes, bytearray)):
        raise TypeError("Secret S must be bytes")
    if len(S)<MIN_BYTES:
        raise ValueError('S must be longer')
    info = 'file-encryption'.encode()
    hkdf = HKDF(
        algorithm = hashes.SHA256(), 
        length = 32,
        info = info)
    key_material = hkdf.derive(S)
    return key_material


def generate_all_keys(S):
    private_key, public_key = generate_authentication_key(S)
    enc_material = generate_encryption_material(S)
    return private_key, public_key, enc_material