
import numpy as np

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


# See https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
def rcon(i: int) -> 

def keyExpansion(encryption_key: bytes):
	# Thanks wikipedia https://en.wikipedia.org/wiki/AES_key_schedule  !!!
	if len(encryption_key) != 16:
		fail("Encryption key must be 128 bits in length! Other lengths are not supported!")

	N = (len(encryption_key)*8)//32 # Length of key in bits divided by 32
	R = 10

	
	

def main():
	encryption_key = "oofoof"
	expanded_key = keyExpansion(bytes(encryption_key))



if __name__=="__main__":

	exit(main())


