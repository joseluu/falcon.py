import falcon
from encoding import pack_pk, unpack_sk, explode_raw_sk
from bitstring import Bits, BitArray # https://bitstring.readthedocs.io/en/stable/bits.html

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def test_KAT():
    fileKat = open('falcon512-KAT.rsp','r')
    i=0
    for lineKat in fileKat:
        lineKat = lineKat[:-1]
        if lineKat.startswith('msg ='):
            msg = lineKat[6:]
            #print ("message %s" % msg)
        if lineKat.startswith('pk ='):
            pk = lineKat[5:]
        if lineKat.startswith('sk ='):
            sk = lineKat[5:]
        if lineKat.startswith('sm ='):
            sm = lineKat[5:]
            check_KAT(msg, pk, sk, sm)
            i=i+1
        if lineKat.startswith('count ='):
            count = lineKat[8:]
            print ("\ntest %s" % count)
    
def check_KAT(msg, pk, sk, sm):
    check_keys(pk, sk)
    check_signature(pk, msg, sm)

def check_keys(pk, sk):
    raw_sk = unpack_sk(sk)
    [f, g, F, G] = explode_raw_sk(512, raw_sk)
    secret_key = falcon.SecretKey(512,[f,g,F,G])
    public_key = falcon.PublicKey(secret_key)  
    valid_or_not = (pk.casefold() == pack_pk(public_key.h).casefold())
    print("public key valid? %s" % ("\u2705" if valid_or_not else "\u274C"))


def check_signature(pk, msg, kat_sig_hex):
    declared_length = int(kat_sig_hex[:4],16)
    sig_hex = "39" + kat_sig_hex[4:84] + kat_sig_hex [2-declared_length *2:] # remove declared length, add prefix and nonce, add signature skipping the 0x29 prefix
    public_key = falcon.PublicKey(pk = pk)
    sig_bytes =  bytes.fromhex(sig_hex)
    message = bytes.fromhex(msg)
    valid_or_not = public_key.verify(message , sig_bytes)
    print("signature  valid? %s" % ("\u2705" if valid_or_not else "\u274C"))

test_KAT()
