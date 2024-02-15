
import numpy as np
import rijndael

'''
The key size used for an AES cipher specifies the number of transformation rounds that convert the input, called the plaintext, into the final output, called the ciphertext. The number of rounds are as follows:

10 rounds for 128-bit keys.
12 rounds for 192-bit keys.
14 rounds for 256-bit keys.
'''

def fail(msg: str):
	print("[-] "+str(msg))
	exit(1)


def encrypt(state, expanded_key, num_rounds):
	# State is a 4x4 matrix which each element is one byte
	# expanded key is the expanded key
	# num rounds is the number of rounds.
	cur_key = 0

'''
i	1	2	3	4	5	6	7	8	9	10
rci	01	02	04	08	10	20	40	80	1B	36

0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
'''
RCON_VALUES = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36] # index is i and value is... ya know... the value of rcon_i .
# See https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
def rcon(i: int) -> bytes:
	return bytes([RCON_VALUES[i - 1], 0, 0, 0])

# Also define RotWord as a one-byte left circular shift:[note 6]
def RotWord(word: bytes) -> bytes:
	# The word should actually be a word
	assert len(word) == 4
	return bytes([word[1], word[2], word[3], word[0]])

def S(x: int) -> int:
	# https://en.wikipedia.org/wiki/Rijndael_S-box
	return rijndael.S_BOX[x]

def test_S() -> None:
	assert rijndael.S_BOX[0x9a] == 0xb8

def SubWord(word: bytes) -> bytes:
	assert len(word) == 4
	return bytes([S(x) for x in word])

VALID_VERSIONS = ["128", "192", "256"]

def xor_bytes(a: bytes, b: bytes) -> bytes:
	assert len(a) == len(b)
	return bytes([a[i] ^ b[i] for i in range(len(a))])

# This is the main key expansion function which does the heavy lifting.
def W(i: int, N: int, K: bytes, W: list) -> bytes: # The W list is being filled as we go.
	if i < N:
		return K[i]
	elif i >= N and (i % N == 0 % N):
		return xor_bytes(xor_bytes((W[i-N]), SubWord(RotWord(W[i-1]))), rcon(i//N))
	elif i >= N and N > 6 and (i % N == 4 % N):
		return xor_bytes(W[i-N], SubWord(W[i-1]))
	else:
		return xor_bytes(W[i-N], W[i-1])

def pad_key(orig_key: bytes, N: int) -> list: # This basically returns K
	if len(orig_key) > N*4: # If the amount of words is greater than N , then the key is too long.
		print("Key length too long! Choose a shorter encryption key or choose bigger AES version!")
		exit()
	return orig_key + bytes([0 for _ in range(N*4 - len(orig_key))])

def splice_K(encryption_key: bytes) -> list:
	assert len(encryption_key) % 4 == 0
	return [encryption_key[x:x+4] for x in range(0, len(encryption_key),4)]


def encrypt(encryption_key: bytes, AES_version: str, plaintext: bytes):
	# Thanks wikipedia https://en.wikipedia.org/wiki/AES_key_schedule  !!!
	#if len(encryption_key) != 16:
	#	fail("Encryption key must be 128 bits in length! Other lengths are not supported!")
	
	# N as the length of the key in 32-bit words: 4 words for AES-128, 6 words for AES-192, and 8 words for AES-256
	# K0, K1, ... KN-1 as the 32-bit words of the original key
	# R as the number of round keys needed: 11 round keys for AES-128, 13 keys for AES-192, and 15 keys for AES-256
	# W0, W1, ... W4R-1 as the 32-bit words of the expanded key
	assert AES_version in VALID_VERSIONS
	num_bits = int(AES_version)
	N = (num_bits)//32 # Length of key in bits divided by 32
	R = 10+((VALID_VERSIONS.index(AES_version)*2)+1)
	encryption_key = pad_key(encryption_key, N)
	assert len(encryption_key) == N*4
	# Splice K
	K = splice_K(encryption_key)
	# Now here is the actual key expansion.
	W_list = []
	for i in range(4*R): # We include 4R.
		W_list.append(W(i, N, K, W_list))
	# Ok, so now the expanded key is in W_list
	#return W_list
	print(W_list)
	return
def run_tests() -> None:
	test_S()
	return

def main():
	run_tests() # Sanity tests.
	encryption_key = "oofoof"
	expanded_key = encrypt(bytes(encryption_key, encoding="ascii"), "128", "sampledata")



if __name__=="__main__":

	exit(main())


