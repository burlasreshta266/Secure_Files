import secrets

MIN_BITS = 128

def fuzzy_extractor(bits):
    # validate bits
    if not bits:
        raise ValueError("length of bits must be larger")
    if len(bits)<MIN_BITS:
        raise ValueError("length of bits must be larger")
    for x in bits:
        if x!='0' and x!='1':
            raise ValueError("bits must contain only 1 or 0")
        
    # generate secret
    n = len(bits)
    S = "".join(secrets.choice("01") for _ in range(n))

    # generate helper data
    helper = []
    for i in range(n):
        h = int(bits[i]) ^ int(S[i])
        helper.append(str(h))

    return S, "".join(helper)

def validate_S(S):
    if len(S)<MIN_BITS:
        return False
    for x in S:
        if x!='0' and x!='1':
            return False
    return True