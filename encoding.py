"""
Compression and decompression routines for signatures.
"""
from bitstring import Bits, BitArray # https://bitstring.readthedocs.io/en/stable/bits.html

#pack https://stackoverflow.com/questions/5066119/how-to-pack-arbitrary-bit-sequence-in-python
def pack_pk(pk_int_array):
    b = BitArray().join(BitArray(uint=i, length=14) for i in pk_int_array)
    return "09" + b.tobytes().hex()

def unpack_pk(pk_hex):
    if pk_hex[:2] != "09":
        return "Error: invalid sk, should begin with 0x59"
    s = Bits(bytes.fromhex(pk_hex[2:]))
    r = []
    i = 0
    for packed in s.cut(14):
        b = BitArray(packed)
        r.append(b.uint)
    return r


def explode_raw_sk(n, raw_sk):
    f = []
    g = []
    F = []
    G = []
    for i in range(n):
        f.append(int(raw_sk[ i * 2 : i * 2 + 2], 16) - 128)
        g.append(int(raw_sk[ (n+i) * 2 :  (n+i) * 2+2], 16) - 128)
        F.append(int(raw_sk[  (2*n+i) * 2 : (2*n+i) * 2+2], 16) - 128)
        if len(raw_sk) == 4 * n:
            G.append(int(raw_sk[  (3*n+i) *2 : (3*n+i) * 2+2], 16) - 128)
    return [f, g, F, G]

# decoding bit packed buffer: https://stackoverflow.com/questions/39663/what-is-the-best-way-to-do-bit-field-manipulation-in-python
def unpack_sk(sk_hex):
    if sk_hex[:2] != "59":
        return "Error: invalid sk, should begin with 0x59"
    s = Bits(bytes.fromhex(sk_hex[2:]))
    r = bytearray()
    i=0
    for packed in s.cut(6):
        b = BitArray(packed)
        if (b.startswith('0b1')): # negative
            b.prepend('0b11')
        else:
            b.prepend('0b00')
        r.append(b.int+128) # emulate naive encoder which adds 128
    return r.hex()

def compress(v, slen):
    """
    Take as input a list of integers v and a bytelength slen, and
    return a bytestring of length slen that encode/compress v.
    If this is not possible, return False.

    For each coefficient of v:
    - the sign is encoded on 1 bit
    - the 7 lower bits are encoded naively (binary)
    - the high bits are encoded in unary encoding
    """
    u = ""
    for coef in v:
        # Encode the sign
        s = "1" if coef < 0 else "0"
        # Encode the low bits
        s += format((abs(coef) % (1 << 7)), '#09b')[2:]
        # Encode the high bits
        s += "0" * (abs(coef) >> 7) + "1"
        u += s
    # The encoding is too long
    if len(u) > 8 * slen:
        return False
    u += "0" * (8 * slen - len(u))
    w = [int(u[8 * i: 8 * i + 8], 2) for i in range(len(u) // 8)]
    x = bytes(w)
    return x


def decompress(x, slen, n):
    """
    Take as input an encoding x, a bytelength slen and a length n, and
    return a list of integers v of length n such that x encode v.
    If such a list does not exist, the encoding is invalid and we output False.
    """
    if (len(x) > slen):
        print("Too long")
        return False
    w = list(x)
    u = ""
    for elt in w:
        u += bin((1 << 8) ^ elt)[3:]
    v = []

    # Remove the last bits
    while u[-1] == "0":
        u = u[:-1]

    try:
        while (u != "") and (len(v) < n):
            # Recover the sign of coef
            sign = -1 if u[0] == "1" else 1
            # Recover the 7 low bits of abs(coef)
            low = int(u[1:8], 2)
            i, high = 8, 0
            # Recover the high bits of abs(coef)
            while (u[i] == "0"):
                i += 1
                high += 1
            # Compute coef
            coef = sign * (low + (high << 7))
            # Enforce a unique encoding for coef = 0
            if (coef == 0) and (sign == -1):
                return False
            # Store intermediate results
            v += [coef]
            u = u[i + 1:]
        # In this case, the encoding is invalid
        if (len(v) != n):
            return False
        return v
    # IndexError is raised if indices are read outside the table bounds
    except IndexError:
        return False
