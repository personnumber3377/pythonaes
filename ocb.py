
# This file is partly based on this: https://www.researchgate.net/publication/322878834_The_offset_codebook_OCB_block_cipher_mode_of_operation_for_authenticated_encryption#pf4

from main import * # Import AES functions.
from test_ocb import *

def ntz(n: int) -> int:
    assert isinstance(n, int)
    count = 0
    while not ((1 << count) & n):
        count += 1
    return count

def E_K(data: bytes, key: bytes) -> bytes: # This is the E_K function. This is basically just the encryption of data plaintext with a key with aes.
    # The data should be the block length
    assert len(data) == 16
    # encrypt(data: bytes, key: bytes, mode="ECB", encryption=True, iv=None)
    return encrypt(data, key, mode="ECB", encryption=True, iv=None) # Just use the ECB mode for now, I assume that OCB1 uses ECB.

def R(N: bytes, key: bytes) -> bytes: # N is the nonce
    # R = E_K(N XOR L)
    return E_K(xor_bytes(N, L0(key)), key) # Data is not used in generating R.


def L0(key: bytes) -> bytes: # This is L(0) = L = E_K(0^n)
    # Just encrypt a lot of zeroes with the specified key.
    return E_K(bytes([0 for _ in range(16)]), key)

def L(i: int, key: bytes, prev_L=None) -> bytes: # This creates the L(i) thing. This is used in generating the Z list.
    if i == 0:
        return L0(key)
    else:
        # get the previous element.
        assert prev_L != None
        return poly_mul(2, prev_L, divisor=0x100000000000000000000000000000085) # 0x100000000000000000000000000000085 aka x^128 + x^7 + x^2 + 1

def Z(i: int, key: bytes, N: bytes, prev_Z=None, prev_L=None) -> list: # This generates the Z array.
    print("i inside Z: "+str(i))
    if i == 0: # Z[1]
        
        return L0(key), xor_bytes(L0(key), R(N,key))
    else: # Z[i]
        assert prev_Z != None # We should define the previous Z value.
        assert prev_L != None

        return L(ntz(i), key, prev_L=prev_L), xor_bytes(prev_Z, L(ntz(i), key, prev_L=prev_L)) # Z(i - 1) XOR L(ntz(i))

def generate_Z_list(m: int, key: bytes, N: bytes) -> tuple: # m is the number of data blocks.
    out_Z_list = []
    out_L_list = []
    for i in range(m+1):
        print("i == "+str(i))
        if i == 0:

            new_L, new_Z = Z(0, key, N, prev_Z=None, prev_L=None)
            out_L_list.append(new_L)
            out_Z_list.append(new_Z)
        else:
            print("in the else case: "+str(i))
            print("out_L_list[-1] == "+str(print_hex(out_L_list[-1]))) # I think the first out_L_list is correct.
            print("out_Z_list[-1] == "+str(print_hex(out_Z_list[-1]))) # 
            new_L, new_Z = Z(i, key, N, prev_Z=out_Z_list[-1], prev_L=out_L_list[-1])
            print("print_hex(new_L) == "+str(print_hex(new_L)))
            print("print_hex(new_Z) == "+str(print_hex(new_Z)))
            assert print_hex(out_Z_list[-1]) != print_hex(new_Z)
            out_L_list.append(new_L)
            out_Z_list.append(new_Z)
    return out_L_list, out_Z_list # Return L, and Z

def generate_nonce() -> bytes: # Basically generates a random sequence of 16 bytes. (NOTE: NOT CRYPTOGRAPHICALLY SECURE!!!!)
    return bytes([random.randrange(0,256) for _ in range(16)])

# Here is the OCBv1 encryption function.
# def encrypt(data: bytes, key: bytes, mode="ECB", encryption=True, iv=None) -> bytes:
def ocb_ver_1_encrypt(data: bytes, key: bytes, nonce=None, test=False) -> bytes:
    '''
    The  message  M  to  be encrypted  and  authenticated  is  divided  into  n-bit  blocks,  with  the  exception of  the  last  block,  which  may  be  less  than  n  bits.  Typically,  n = 128.  Only  a single  pass  through  the  message  is  required  to  generate  both  the  ciphertext and the  authentication code.  The total number  of blocks is  m = dlen(M)/ne.
    '''

    version = get_aes_ver_from_key(key)

    data_blocks = split_data_blocks(data) # here is the splitting of the data to blocks.
    '''
    Note  that the  encryption structure  for  OCB  is  similar  to that  of electronic codebook  (ECB)  mode.  Each  block  is  encrypted  independently  of  the  other blocks, so that it is possible to perform all m encryptions simultaneously. With ECB,  if  the  same  b-bit  block  of  plaintext  appears  more  than  once  in  the message,  it always  produces  the same  ciphertext.  Because of  this,  for lengthy messages,  the  ECB  mode  may  not  be  secure.  OCB  eliminates  this  property by  using  an  offset  Z[i]  for  each  block  M[i],  such  that  each  Z[i]  is  unique; the  offset  is  XORed  with  the  plaintext and  XORed  again  with  the encrypted output.  Thus, with  encryption  key  K, we  have

    C[i] = E_K(M[i] XOR Z[i]) XOR Z[i]

    where E_K[X] is the encryption  of  plaintext X using key K,  and XOR is the bitwise exclusive or operator.
    '''
    # Generate Nonce.
    
    # ...

    # The calculation of the Z[i] is somewhat complex and is summarized in the following equations:
    # L(0) = L = E_K(0^n) , where 0^n is consists of n zero bits.
    # R = E_K(N XOR L)
    # L(i) = 2* L(i - 1)
    # Z[1] = L XOR R # I don't know if
    # Z[i] = Z(i - 1) XOR L(ntz(i))

    # generate_Z_list(m: int, key: bytes, N: bytes) -> tuple:

    # num_rounds, expanded_key, reverse_keys = key_expansion(key, version) # Use the 192 bit version instead of the 128

    num_rounds, expanded_key, reverse_keys = key_expansion(key, version) # Use the 192 bit version instead of the 128
    m = math.ceil(len(data)/((int(version))//8)) # m = ceil(len(M)/n) , where n is the version integer.
    if nonce == None: # Check for assigned nonce
        nonce = generate_nonce() # Just create random bytes.
    L_list, Z_list = generate_Z_list(m, key, nonce)
    print("Here is the L list: "+str(L_list))
    print("Here is the Z list: "+str(Z_list))
    print("L list as printed hex: "+str(print_hex(L_list)))
    print("Z list as printed hex: "+str(print_hex(Z_list)))
    return L_list, Z_list # Stub for now.
    # c6a13b37878f5b826f4f8162a1c8d879c6a13b37878f5b826f4f8162a1c8d879


def main_ocb() -> int:
    run_tests_ocb()
    return 0

if __name__=="__main__":
    exit(main_ocb())