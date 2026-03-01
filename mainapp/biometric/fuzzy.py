import secrets

SECRET_BITS = 128       
BLOCK_SIZE = 5         


def repeat_encode(bitstring, k):
    encoded = []
    for b in bitstring:
        encoded.extend([b] * k)
    return encoded


def repeat_decode(encoded_bits, k):
    if len(encoded_bits) % k != 0:
        raise ValueError("Encoded length not divisible by block size")

    decoded = []
    for i in range(0, len(encoded_bits), k):
        block = encoded_bits[i:i+k]
        ones = block.count('1')
        zeros = block.count('0')
        # deterministic tie-break (default to 0)
        decoded.append('1' if ones > zeros else '0')

    return ''.join(decoded)


def expand_bits(bits, target_len):
    expanded = bits[:]
    while len(expanded) < target_len:
        expanded += bits
    return expanded[:target_len]


def fuzzy_gen(bits_enroll):
    # 1. Generate secret S
    S = ''.join(secrets.choice('01') for _ in range(SECRET_BITS))

    # 2. ECC encode S
    C = repeat_encode(S, BLOCK_SIZE)

    # 3. Expand biometric bits
    bits_expanded = expand_bits(list(bits_enroll), len(C))

    # 4. Create helper data
    helper = [
        str(int(bits_expanded[i]) ^ int(C[i]))
        for i in range(len(C))
    ]

    return S, ''.join(helper)


def fuzzy_rep(bits_login, helper):
    bits_expanded = expand_bits(list(bits_login), len(helper))

    # 2. Recover noisy codeword
    noisy_C = [
        str(int(bits_expanded[i]) ^ int(helper[i]))
        for i in range(len(helper))
    ]

    # 3. ECC decode
    S_recovered = repeat_decode(noisy_C, BLOCK_SIZE)

    if len(S_recovered) != SECRET_BITS:
        raise ValueError("Recovered S has invalid length")

    return S_recovered
