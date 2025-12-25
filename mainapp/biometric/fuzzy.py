from math import ceil
import secrets
from reedsolo import RSCodec, ReedSolomonError

ECC_PADDING = 11
rc = RSCodec(ECC_PADDING)

def bits_to_byte(bits):
    return int(bits, 2).to_bytes(ceil((len(bits)+ECC_PADDING)/8), byteorder='big')

def generate_S(bits):
    inp_bytes = bytearray(bits_to_byte(bits))
    S_length = len(inp_bytes)-ECC_PADDING
    if S_length<=0:
        raise ValueError('Biometric is not long enough')
    S_bytes = secrets.token_bytes(S_length)
    codeword = bytearray(rc.encode(S_bytes))
    if len(codeword)>len(inp_bytes):
        inp_bytes = inp_bytes[:len(codeword)]
    help_list = [codeword[i]^inp_bytes[i] for i in range(len(codeword))]
    helper_bytes = bytes(help_list)
    return S_bytes, helper_bytes

def recover_S(login_bits, helper_bytes):
    login_bytes = bytearray(bits_to_byte(login_bits))
    length = min(len(login_bytes), len(helper_bytes))
    login_bytes = login_bytes[:length]
    helper_bytes = helper_bytes[:length]
    noisy_code = [login_bytes[i]^helper_bytes[i] for i in range(length)]
    try:
        S_recovered, packets_ecc, errs = rc.decode(noisy_code)
        return S_recovered
    except ReedSolomonError:
        return None