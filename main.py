
import numpy as np
import rijndael
import copy
from typing import Iterable 
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
		#print("paskaaa")
		return xor_bytes(W[i-N], W[i-1])

def pad_key(orig_key: bytes, N: int) -> list: # This basically returns K
	if len(orig_key) > N*4: # If the amount of words is greater than N , then the key is too long.
		print("Key length too long! Choose a shorter encryption key or choose bigger AES version!")
		exit()
	return orig_key + bytes([0 for _ in range(N*4 - len(orig_key))])

def pad_plain_text(orig_plaintext: bytes, length: int) -> list:
	return orig_plaintext + bytes([0 for _ in range(length - len(orig_plaintext))])

def splice_K(encryption_key: bytes) -> list:
	assert len(encryption_key) % 4 == 0
	return [encryption_key[x:x+4] for x in range(0, len(encryption_key),4)]


def make_integer_list(W_list: list) -> list:
	out = []
	for mat in W_list:
		# First convert the bytes lists to integers.
		int_mat = [[x for x in b] for b in mat]
		print(int_mat)
		# Now transpose, because the numbers are the wrong way around.
		int_mat = transpose_mat(int_mat)
		out.append(int_mat)
	return out

def key_expansion(encryption_key: bytes, AES_version: str):
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
	#print(W_list)
	#print("length of W_list: "+str(len(W_list)))
	# This cuts the matrix into 4x4 matrixes.
	W_list = [W_list[x:x+4] for x in range(0, len(W_list),4)]
	W_actual = make_integer_list(W_list)
	return R, W_actual


# Thanks to https://stackoverflow.com/questions/952914/how-do-i-make-a-flat-list-out-of-a-list-of-lists
def flatten(items):
	"""Yield items from any nested iterable; see Reference."""
	for x in items:
		if isinstance(x, Iterable) and not isinstance(x, (str, bytes)):
			for sub_x in flatten(x):
				yield sub_x
		else:
			yield x

def print_hex(byte_list: bytes) -> None:
	# print("byte_list == "+str(byte_list))
	# Check if the matrix is a 4x4 state.
	if len(byte_list) == 4 and len(byte_list[0]) == 4 and isinstance(byte_list[0][0], int):
		# Now transpose, because the state is a 4x4 matrix.
		'''
		[[b0,b4,b8,b12],
		[b1,b5,b9,b13],
		[b2,b6,b10,b14],
		[b3,b7,b11,b15]]
		'''

		byte_list = transpose_mat(byte_list)

	flattened_list = list(flatten(byte_list))
	print("length of flattened_list : "+str(len(flattened_list)))
	print("Here is the flattened list: "+str(flattened_list))
	print("flattened_list[0] == "+str(flattened_list[0]))
	#assert len(flattened_list) == 4*4
	#print("="*30)
	out = ""
	#print(flattened_list)
	for x in flattened_list:
		#print("x == "+str(x))
		#print(hex(int.from_bytes(x, byteorder='big')))
		if isinstance(x, bytes):
			for b in x:
				print("b == "+str(b))
				oof = hex(b)[2:]
				if len(oof) == 1:
					oof = "0"+oof
				print("oof == "+str(oof))
				out += oof
		else:
			#out += hex(x)[2:]
			oof = hex(x)[2:]
			if len(oof) == 1:
				oof = "0"+oof
			out += oof
	return out
	#print("="*30)

def test_key_expansion():
	string = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c"
	key = bytes([int(x, base=16) for x in string.split(" ")])
	_, expanded_key = key_expansion(bytes(key), "128")
	print_hex(expanded_key)

def create_state(plaintext: bytes) -> bytes:
	assert len(plaintext) <= 16
	padded_plain_text = pad_plain_text(plaintext, 16)
	assert len(padded_plain_text) == 16
	# Now split into a list and then create a numpy array and then transpose.
	cut_list = [padded_plain_text[x:x+4] for x in range(0, len(padded_plain_text),4)]
	state = [[0 for _ in range(4)] for _ in range(4)]
	# Now transpose the matrix
	for i in range(len(cut_list)):
		for j in range(len(cut_list[0])):
			state[j][i] = cut_list[i][j]
	return state

def SubBytes(input_matrix: list) -> list:
	#input_matrix = flatten(input_matrix)
	#input_matrix = list(input_matrix)
	#out = copy.deepcopy(input_matrix)
	for i in range(len(input_matrix)):
		for j in range(len(input_matrix[0])):
			#print("input_matrix[i][j] == "+str(input_matrix[i][j]))
			#print("rijndael.S_BOX_SPLIT == "+str(rijndael.S_BOX_SPLIT))
			index_integer = input_matrix[i][j]
			ind_x = index_integer & 0b1111
			ind_y = (index_integer & 0b11110000) >> 4
			#print("ind_x == "+str(ind_x))
			#print("ind_y == "+str(ind_y))
			#print("rijndael.S_BOX_SPLIT[8] == "+str(rijndael.S_BOX_SPLIT[8]))
			#print("rijndael.S_BOX_SPLIT == "+str(rijndael.S_BOX_SPLIT))
			input_matrix[i][j] = rijndael.S_BOX_MATRIX[ind_y][ind_x]
	return input_matrix

def InvSubBytes(input_matrix: list) -> list:
	# Reverse of SubBytes.
	return

def shift_row_once(row: list, reverse=False) -> list:
	if not reverse:
		out = [row[i] for i in range(1,len(row))] + [row[0]]
	else:
		out = [row[-1]] + [row[i] for i in range(0,len(row)-1)]
	return out

def shift_row(row: list, n: int, reverse=False) -> list: # This shifts one singular line by n indexes.
	for i in range(n):
		row = shift_row_once(row, reverse=reverse)
	return row

def ShiftRows(input_mat: list) -> list:
	assert len(input_mat) == 4
	assert len(input_mat[0]) == 4
	print("input_mat[1] == "+str(input_mat[1]))
	input_mat[1] = shift_row(input_mat[1], 1)
	print("after: "+str(input_mat[1]))
	input_mat[2] = shift_row(input_mat[2], 2)
	input_mat[3] = shift_row(input_mat[3], 3)
	return input_mat

def InvShiftRows(input_mat: list) -> list:

	assert len(input_mat) == 4
	assert len(input_mat[0]) == 4
	input_mat[1] = shift_row(input_mat[1], 1, reverse=True)
	input_mat[2] = shift_row(input_mat[2], 2, reverse=True)
	input_mat[3] = shift_row(input_mat[3], 3, reverse=True)

	return input_mat

def mat_xor(mat1: list, mat2: list) -> list:
	out = copy.deepcopy(mat2)
	for i in range(len(mat1)):
		for j in range(len(mat2)):
			out[i][j] = out[i][j] ^ mat1[i][j]
	return out

'''
def multiply_vec_mat_polynomial(vec: list, mat: list) -> list: # This is matrix multiplication, but with polynomial.
	out = []
	for i in range(len(mat)):
		cur_line = mat[i]
		assert len(cur_line) == len(vec)
		#out.append(sum(cur_line[i]*vec[i] for i in range(len(vec))))
		# But it’s a slight trickier matrix multiplication, as the sum operation is substituted by xor and multiplication for and.
		oof = [cur_line[i]&vec[i] for i in range(len(vec))] # https://medium.com/quick-code/understanding-the-advanced-encryption-standard-7d7884277e7
		res = 0
		for elem in oof:
			res ^= elem
		out.append(res)
	return out
'''

def mix_col(r: list) -> list:
	a = [0,0,0,0]
	b = [0,0,0,0]
	print("r original: "+str(r))
	assert all([r[i] <=255 for i in range(len(r))])
	for c in range(4):
		a[c] = r[c]
		h = r[c] >> 7
		b[c] = r[c] << 1
		print("b[c] == "+str(b[c]))
		print("h * 0x1B + 0x100 == "+str(hex(h * 0x1B + 0x100)))
		b[c] ^= h * 0x1B
		b[c] &= 0xff # This must be here, because in c code if we try to shift 0x80 << 1 , then it will go to zero, but not in python, so we need to clamp manually.
		print("b[c] final == "+str(b[c]))
	assert all([a[c] == r[c] for c in range(len(r))])
	r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]#; /* 2 * a0 + a3 + a2 + 3 * a1 */
	r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]#; /* 2 * a1 + a0 + a3 + 3 * a2 */
	r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]#; /* 2 * a2 + a1 + a0 + 3 * a3 */
	r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]#; /* 2 * a3 + a2 + a1 + 3 * a0 */
	print("r == "+str(r))
	assert all([r[i] <=255 for i in range(len(r))])
	return r

def byte_check(int_list: list) -> list:
	return [x & 0xff for x in int_list]

def mix_one_column(in_list: list) -> list:
	'''
	This function multiplies the vector in_list with this matrix:
	[[2,3,1,1],
	[1,2,3,1],
	[1,1,2,3],
	[3,1,1,2]]
	'''

	out = mix_col(in_list)
	return out


def transpose_mat(input_mat: list) -> list:
	# The matrixes which are inputted to this function should be 4x4 matrixes.
	assert len(input_mat) == 4
	assert len(input_mat[0]) == 4
	out = copy.deepcopy(input_mat)
	for i in range(len(input_mat)):
		for j in range(len(input_mat[0])):
			out[j][i] = input_mat[i][j]
	return out

def MixColumns(input_matrix: list) -> list:
	# Get each column and then apply the matrix transformation.
	out = []
	print("input_matrix to MixColumns == "+str(input_matrix))
	for i in range(4):
		cur_column = [input_matrix[j][i] for j in range(4)]
		print("Here is the cur_column: "+str(cur_column))
		out.append(mix_one_column(cur_column))
	out = transpose_mat(out)
	print("Outputting this from MixColumns: "+str(out))
	return out

def AddRoundKey(input_mat: list, i: int, W: list) -> list:
	subkey = get_key_matrix(i, W)
	print("subkey == "+str(subkey))
	print("input_mat == "+str(input_mat))
	print("subkey == "+str(subkey))
	#input_mat = mat_xor(input_mat, subkey) # These need to be the other way around, because bytes type object can
	input_mat = mat_xor(subkey, input_mat)
	return input_mat

def get_key_matrix(i: int, W: list) -> list:
	# This get's the correct 4x4 matrix from the expanded key.
	cor_key_thing = W[i]
	return cor_key_thing
	#return rijndael.S_BOX_SPLIT[i]

def BoundsCheck(state: list) -> list:
	for i in range(len(state)):
		for j in range(len(state[0])):
			state[i][j] &= 0xff
	return state

def encrypt_state(expanded_key: list, plaintext: bytes, num_rounds: int, W_list: list) -> bytes:
	state = create_state(plaintext)
	# Initial round key addition:
	print("Here is the expanded key: "+str(expanded_key))
	print("Here is the length of the key: "+str(len(expanded_key)))
	print("round[0].input : "+str(print_hex(state)))
	state = AddRoundKey(state, 0, W_list)
	print("round[0].k_sch : "+str(print_hex(expanded_key)))
	# 9, 11 or 13 rounds:
	for i in range(1,num_rounds-1):
		print("round["+str(i)+"].start == "+str(print_hex(state)))
		state = SubBytes(state)
		print("round["+str(i)+"].s_box == "+str(print_hex(state)))
		state = ShiftRows(state)
		print("round["+str(i)+"].s_row == "+str(print_hex(state)))
		state = MixColumns(state)
		print("round["+str(i)+"].m_col == "+str(print_hex(state)))
		state = BoundsCheck(state) # This here to bounds check every element to the inclusive range 0-255 .
		state = AddRoundKey(state, i, W_list)
		print("round["+str(i)+"].k_sch == "+str(print_hex(state)))
	# Final round (making 10, 12 or 14 rounds in total):
	state = SubBytes(state)
	print("round["+str(num_rounds-1)+"].s_box == "+str(print_hex(state)))
	state = ShiftRows(state)
	print("round["+str(num_rounds-1)+"].s_row == "+str(print_hex(state)))
	state = AddRoundKey(state, num_rounds-1, W_list)
	print("round["+str(num_rounds-1)+"].k_sch == "+str(print_hex(state)))
	state = BoundsCheck(state)
	print("Final state after encryption: "+str(print_hex(state)))
	return print_hex(state)

'''
InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])

begin

byte state[4,Nb]

state = in

AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4

for round = Nr-1 step -1 downto 1

InvShiftRows(state) // See Sec. 5.3.1

InvSubBytes(state) // See Sec. 5.3.2

AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])

InvMixColumns(state) // See Sec. 5.3.3

end for

InvShiftRows(state)

InvSubBytes(state)

AddRoundKey(state, w[0, Nb-1])

out = state

end
 
'''

def decrypt_state(expanded_key: list, encrypted_data: list, num_rounds: int, W_list: list) -> str:
	# This is the main decryption function.
	state = create_state(encrypted_data)
	state = AddRoundKey(state, num_rounds-1, W_list)
	# for round = Nr-1 step -1 downto 1
	for i in range(num_rounds-1, 1, -1):
		# InvShiftRows(state) 
		state = InvShiftRows(state)
		state = InvSubBytes(state)

def test_print_hex() -> None:
	test_mat = [[0,4,8,12],
				[1,5,9,13],
				[2,6,10,14],
				[3,7,11,15]]
	# Now test the printing
	print("Here is the test output.")
	out = print_hex(test_mat)
	print(out)
	# 000102030405060708090a0b0c0d0e0f
	assert out == "000102030405060708090a0b0c0d0e0f" # Should be this

def test_transpose_mat() -> None:
	test_mat = [[0,4,8,12],
				[1,5,9,13],
				[2,6,10,14],
				[3,7,11,15]]
	out = transpose_mat(test_mat)
	assert out == [[0,1,2,3],
				[4,5,6,7],
				[8,9,10,11],
				[12,13,14,15]]

def test_shift() -> None:
	paska = [[0,1,2,3],
			[4,5,6,7],
			[8,9,10,11],
			[12,13,14,15]]
	old_paska = copy.deepcopy(paska)
	ret = ShiftRows(paska)
	oof = [[0,1,2,3],
			[5,6,7,4],
			[10,11,8,9],
			[15,12,13,14]]
	assert ret == oof
	# Now test inverse function.
	oof = InvShiftRows(paska)
	assert oof == old_paska
	print("Passed test_shift!")



def run_tests() -> None:
	test_transpose_mat()
	test_S()
	test_key_expansion()
	test_print_hex()
	# Test the reverse functions. If there is a function called f and an inverse function called F , then f(F(x)) = F(f(x)) = x
	test_shift()
	return

def main():
	run_tests() # Sanity tests.
	encryption_key = "oofoof"
	num_rounds, expanded_key = key_expansion(bytes(encryption_key, encoding="ascii"), "128")
	# 00112233445566778899aabbccddeeff
	# example_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
	#example_plaintext = bytes.fromhex("004488cc115599dd2266aaee3377bbff")
	example_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
	key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
	print("Here is the key: "+str(key))
	#key = bytes.fromhex("004488cc115599dd2266aaee3377bbff")
	num_rounds, expanded_key = key_expansion(key, "128")
	encrypted = encrypt_state(expanded_key, example_plaintext, num_rounds, expanded_key)
	print(encrypted)
	# Now the encrypted data is in "encrypted". Now decrypting it, should return in the original plaintext.

	print("Done!")
	return 0

if __name__=="__main__":

	exit(main())


