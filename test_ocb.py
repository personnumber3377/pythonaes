from ocb import *
from main import *

def test_ntz() -> None:
    # 8 == 0b1000
    # 11 = 0b1011
    assert ntz(8) == 3
    assert ntz(11) == 0
    print("test_ntz passed!!!")
    return

def test_ocb1_encrypt() -> None:
    # There are test vectors at https://datatracker.ietf.org/doc/html/rfc7253
    # "K : 000102030405060708090A0B0C0D0E0F"
    # K, string of KEYLEN bits                      // Key
    # N, string of no more than 120 bits            // Nonce
    # N : BBAA99887766554433221100
    # C, string of at least TAGLEN bits             // Ciphertext
    # A, string of any length                       // Associated data
    #nonce = bytes([0x41 for _ in range(16)]) # ASCII "AAAA..."
    nonce = bytes.fromhex("00"*(16-(len("BBAA99887766554433221100")//2))+"BBAA99887766554433221100") # This should only be 120 bits long aka 15 bytes
    #assert len(nonce) == 15
    assert len(nonce) == 16
    #key = bytes([0x42 for _ in range(16)]) # ASCII "BBBB..."
    key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    # A: 0001020304050607

    # L_* = ENCIPHER(K, zeros(128))
    data = bytes([0 for _ in range(16)])

    # def ocb_ver_1_encrypt(data: bytes, key: bytes, nonce=None, test=False) -> bytes:

    L, Z = ocb_ver_1_encrypt(data, key, nonce=nonce, test=True) # Encrypt.
    print("Here is L: "+str(L))
    # Later on in the test stuff:
    '''
    L_*       : C6A13B37878F5B826F4F8162A1C8D879
    L_$       : 8D42766F0F1EB704DE9F02C54391B075
    L_0       : 1A84ECDE1E3D6E09BD3E058A8723606D
    L_1       : 3509D9BC3C7ADC137A7C0B150E46C0DA
    bottom    : 15 (decimal)
    Ktop      : 9862B0FDEE4E2DD56DBA6433F0125AA2
    Stretch   : 9862B0FDEE4E2DD56DBA6433F0125AA2FAD24D13A063F8B8
    Offset_0  : 587EF72716EAB6DD3219F8092D517D69
    Offset_1  : 42FA1BF908D7D8D48F27FD83AA721D04
    Offset_2  : 77F3C24534AD04C7F55BF696A434DDDE
    Offset_*  : B152F972B3225F459A1477F405FC05A7
    Checksum_1: 000102030405060708090A0B0C0D0E0F
    Checksum_2: 10101010101010101010101010101010
    Checksum_*: 30313233343536379010101010101010

    '''

def run_tests_ocb() -> None:
    test_ntz()
    test_ocb1_encrypt()
    return



