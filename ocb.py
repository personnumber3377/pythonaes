
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



def L0(key: bytes) -> bytes: # This is L(0) = L = E_K(0^n)
    # Just encrypt a lot of zeroes with the specified key.
    return E_K(bytes([0 for _ in range(16)]), key)

def L(i: int, key: bytes, cur_L_list: list) -> bytes: # This creates the L(i) thing. This is used in generating the Z list.
    if i == 0:
        return L0(key)
    else:
        # get the previous element.
        return 
def Z() -> list: # This generates the Z array.



# Here is the OCBv1 encryption function.
# def encrypt(data: bytes, key: bytes, mode="ECB", encryption=True, iv=None) -> bytes:
def ocb_ver_1_encrypt(data: bytes, key: bytes) -> bytes:
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

def main_ocb() -> int:
    run_tests_ocb()
    return 0

if __name__=="__main__":
    exit(main_ocb())