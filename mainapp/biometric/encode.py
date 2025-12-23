BITS_PER_BIN = 3

def encode_bins(bins):
    if not bins:
        raise ValueError("Bins must not be empty")
    
    bit_list = []
    for x in bins:
        b = f'{x:0{BITS_PER_BIN}b}'
        bit_list.append(b)

    return "".join(bit_list)


def get_bit_length(n):
    if n<=0:
        raise ValueError("number of bins must be more than zero")
    return n*BITS_PER_BIN
