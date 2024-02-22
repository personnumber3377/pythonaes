import numpy as np
import rijndael
import copy
from typing import Iterable
import math
import testdatahelper # This is for MIX_COL_TESTS (for now.)
from tests import *
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

def SubWord(word: bytes) -> bytes:
	assert len(word) == 4
	return bytes([S(x) for x in word])

VALID_VERSIONS = ["128", "192", "256"]

def xor_bytes(a: bytes, b: bytes) -> bytes:
	assert len(a) == len(b)
	return bytes([a[i] ^ b[i] for i in range(len(a))])

# This is the main key expansion function which does the heavy lifting.
def W(i: int, N: int, K: bytes, W: list, version="128") -> bytes: # The W list is being filled as we go.
	# This should be here, as of section 5.2 , but if this is here, then the wrong answer is produced. :D   IDK .
	'''
	if version == "256": # This is the special case for the 256 bit key
		# Taken from https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
		# See section 5.2
		
		#It is important to note that the Key Expansion routine for 256-bit Cipher Keys (Nk = 8) is slightly different than for 128- and 192-bit Cipher Keys. If Nk = 8 and i-4 is a multiple of Nk, then SubWord() is applied to w[i-1] prior to the XOR.
		
		if (i-4) % 8 == 0: # If Nk = 8 and i-4 is a multiple of Nk, then...
			# ... SubWord() is applied to w[i-1] prior to the XOR.
			#W_list[-1] = SubWord(W_list[-1])
			W[-1] = SubWord(W[-1])
	'''
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
		assert False
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
		W_list.append(W(i, N, K, W_list, version=AES_version)) # Here the version is now passed to this function, because in the 256 bit version we need to do an additional step.
		
	# Ok, so now the expanded key is in W_list
	#return W_list
	#print(W_list)
	#print("length of W_list: "+str(len(W_list)))
	# This cuts the matrix into 4x4 matrixes.
	W_list = [W_list[x:x+4] for x in range(0, len(W_list),4)]
	W_actual = make_integer_list(W_list)
	inverse_key_stuff = copy.deepcopy(W_actual)
	# Now do the stuff...
	'''
	for round = 1 step 1 to Nr-1
		InvMixColumns(dw[round*Nb, (round+1)*Nb-1]) 
	'''
	
	inverse_key_mat = [inverse_key_stuff[0]] # add the initial key shit.
	#inverse_key_mat = []
	for k in range(1,len(inverse_key_stuff)):
		# Here do the inverse shit.
		inverse_key = [] # This is the 4x4 matrix.
		assert len(inverse_key_stuff[k]) == 4 # Sanity.
		cur_mat = inverse_key_stuff[k]
		for l in range(4):
			cur_column = [cur_mat[j][l] for j in range(4)]
			cur_column = rev_mix_column(cur_column)
			inverse_key.append(cur_column)
		inverse_key_mat.append(inverse_key)

	return R, W_actual, inverse_key_mat # inverse_key_mat is basically the reverse key list, where each element is the 4x4 key matrix.


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
	#print("length of flattened_list : "+str(len(flattened_list)))
	#print("Here is the flattened list: "+str(flattened_list))
	#print("flattened_list[0] == "+str(flattened_list[0]))
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
				#print("oof == "+str(oof))
				out += oof
		else:
			#out += hex(x)[2:]
			oof = hex(x)[2:]
			if len(oof) == 1:
				oof = "0"+oof
			out += oof
	return out
	#print("="*30)

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

def access_table(table: list, index: int) -> int: # This is used to access the S box and the reverse S box.
	assert index <= 255 and index >= 0 # Sanity check.
	ind_x = index & 0b1111
	ind_y = (index & 0b11110000) >> 4
	return table[ind_y][ind_x]

def SubBytes(input_matrix: list, table=rijndael.S_BOX_MATRIX) -> list:
	for i in range(len(input_matrix)):
		for j in range(len(input_matrix[0])):
			input_matrix[i][j] = access_table(table, input_matrix[i][j])
	return input_matrix

def InvSubBytes(input_matrix: list) -> list:
	# Reverse of SubBytes. Otherwise similar, but use the reverse matrix instead.
	return SubBytes(input_matrix, table=rijndael.S_BOX_MATRIX_REV)


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

def bits(n: int) -> int:
	return math.ceil(math.log(n+1,2))



def poly_mod(dividend: int, divisor: int) -> int:
	# First align the integers for the long division.
	#print("Called poly_mod.")
	#if dividend < divisor:
	#	return dividend
	# This is used to align
	num_bits_dividend = bits(dividend)
	num_bits_divisor = bits(divisor)
	# We need to shift the divisor such that the most significant bits are aligned.
	diff = num_bits_dividend - num_bits_divisor
	if diff < 0:
		return dividend
	divisor <<= diff # Align.
	# Main loop.
	#print("diff == "+str(diff))
	assert diff >= 0
	while diff >= 0:
		#print("Dividend: "+str(bin(dividend)[2:]))
		#print("Divisor: "+str(bin(divisor)[2:]))
		if ((divisor) & dividend) & (1 << (bits(divisor)-1)):
			# We are aligned, therefore divide (XOR)
			dividend ^= divisor
		divisor >>= 1 # Shift one to the right
		diff -= 1
	return dividend

def poly_mul(a: int, b: int) -> int: # This function multiplies the polynomial a with b in G(2) and then modulo x**8 + x**4 + x**3 + x**2 + x + 1.
	out = 0
	k = b
	while k: # This basically shifts left and then if the current bit is a one, then xor the current thing with the thing.
		cur_bit = k & 1 # current bit.
		if cur_bit:
			out ^= (a) # xor if bit is one.
		# shift
		a <<= 1
		k >>= 1
	# Now modulo in polynomial in GF(2) # See https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
	#print("passing "+str(hex(out))+" to poly mod.")
	out = poly_mod(out, 0x11B)
	#print("result is this: "+str(hex(out)))
	assert out < 0x11B
	assert out < 256
	return out

def rev_mix_column(r: list) -> list: # This is used in InvMixColumns.
	a = [0,0,0,0]
	b = [0,0,0,0]
	c = [0,0,0,0]
	d = [0,0,0,0]
	e = [0,0,0,0]
	'''
	/* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 0xe
	 * The array 'c' is each element of the array 'a' multiplied by 0x9
	 * The array 'd' is each element of the array 'a' multiplied by 0xd
	 * The array 'e' is each element of the array 'a' multiplied by 0xb
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */ 
	'''
	for k in range(4): # Can't use 'c' here, because it is already a name of a list.
		a[k] = r[k]
		#b[k] = r[k] * 0xe # multiplied by 0xe
		#c[k] = r[k] * 0x9 # multiplied by 0x9
		#d[k] = r[k] * 0xd # multiplied by 0xd
		#e[k] = r[k] * 0xb # multiplied by 0xb
		b[k] = poly_mul(r[k], 0xe)
		c[k] = poly_mul(r[k], 0x9)
		d[k] = poly_mul(r[k], 0xd)
		e[k] = poly_mul(r[k], 0xb)
		# Sanity check.
		int_list = [b[k], c[k], d[k], e[k]]
		#print("int_list == "+str(int_list))
		assert all([(x >= 0 and x < 0x11B) for x in int_list])

	# Now we do something similar to what we did in mix_col
	r[0] = b[0] ^ e[1] ^ d[2] ^ c[3]
	r[1] = c[0] ^ b[1] ^ e[2] ^ d[3]
	r[2] = d[0] ^ c[1] ^ b[2] ^ e[3]
	r[3] = e[0] ^ d[1] ^ c[2] ^ b[3]
	assert all([(x >= 0 and x <= 255 for x in r)]) # Sanity checking.
	#print("Returning this from rev_mix_column: "+str(r))
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

def MixColumns(input_matrix: list, reverse=False) -> list:
	# Get each column and then apply the matrix transformation.
	out = []
	sanity_copy = copy.deepcopy(input_matrix)
	assert all([x >= 0 and x <= 255 for x in flatten(sanity_copy)]) # Here is the sanity check on the input.
	#print("input_matrix to MixColumns == "+str(input_matrix))
	for i in range(4):
		cur_column = [input_matrix[j][i] for j in range(4)]
		print("Here is the cur_column: "+str(cur_column))
		if not reverse:

			out.append(mix_one_column(cur_column))
		else:
			print("cur_column: "+str(cur_column))
			reverse_mixing = rev_mix_column(cur_column)
			print("output from rev_mix_column: "+str(reverse_mixing))
			assert all([x >= 0 and x <= 255 for x in reverse_mixing])
			out.append(reverse_mixing)

	print("Outputting this from MixColumns: "+str(out))
	# Sanity checking.
	sanity_copy = copy.deepcopy(out)
	assert all([x >= 0 and x <= 255 for x in flatten(sanity_copy)])
	out = transpose_mat(out)
	return out

def InvMixColumns(input_matrix: list) -> list:
	return MixColumns(input_matrix, reverse=True)

def AddRoundKey(input_mat: list, i: int, W: list, cur_round_num=None) -> list:
	subkey = get_key_matrix(i, W)
	if cur_round_num != None:

		print("round["+str(cur_round_num)+"].ik_sch == "+str(print_hex(subkey)))
	#print("subkey == "+str(subkey))
	#print("input_mat == "+str(input_mat))
	#print("subkey == "+str(subkey))
	#input_mat = mat_xor(input_mat, subkey) # These need to be the other way around, because bytes type object can
	input_mat = mat_xor(subkey, input_mat)
	#print("Here is the output from AddRoundKey: "+str(input_mat))
	return input_mat

def get_key_matrix(i: int, W: list) -> list:
	# This get's the correct 4x4 matrix from the expanded key.
	cor_key_thing = W[i]
	print("Cor key thing: "+str(cor_key_thing))
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

def hex_list_to_str(int_list: list) -> None:
	oof = ''.join([hex(x)+" " for x in int_list])
	oof = oof[:-1]
	#print(oof)
	return oof

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
	print("round[0].iinput: "+str(print_hex(state)))
	#state = AddRoundKey(state, num_rounds-1, W_list)
	print("num_rounds-1 == "+str(num_rounds-1))
	print("len(W_list) == "+str(len(W_list)))
	state = AddRoundKey(state, num_rounds-1, W_list, cur_round_num=0)

	#state = AddRoundKey(state, 0, W_list, cur_round_num=0) # Maybe this will actually work?????
	#print("round[0].ik_sch == "+str(print_hex(state)))
	# for round = Nr-1 step -1 downto 1
	count = 0
	for i in range(num_rounds-2, 0, -1): # zero is not included, so 1 is the final value of i
		count += 1
		# InvShiftRows(state) 
		print("round["+str(count)+"].istart: "+str(print_hex(state)))
		state = InvShiftRows(state)
		print("round["+str(count)+"].is_row: "+str(print_hex(state)))
		state = InvSubBytes(state)
		#print("round["+str(count)+"].im_col: "+str(print_hex(state)))
		state = AddRoundKey(state, i, W_list, cur_round_num=count)
		print("round["+str(count)+"].is_box: "+str(print_hex(state)))
		state = InvMixColumns(state)
		#print("round["+str(count)+"].istart: "+str(print_hex(state)))
	print("End of the loop!!!!")
	state = InvShiftRows(state)
	state = InvSubBytes(state)
	state = AddRoundKey(state, 0, W_list)
	print("Here is the state in decrypt_state before returning: "+str(state))
	return print_hex(state)

def get_aes_ver_from_key(key: bytes) -> str:
	if len(key) > (256//8):
		# Invalid key size.
		print("Invalid key size!!!")
		print("length of key must be less than or equal to 256!!!")
		print("length of key: "+str(len(key)))
		assert False # Invalid key size.
	version = None
	if len(key) > (192//8):
		# key must be 256 bit
		version = "256"
	elif len(key) > (128//8):
		# key must be 192 bit
		version = "192"
	else:
		version = "128" # default to 128 bit key.
	assert version != None # We should have assigned version as of now.
	return version

def split_data_blocks(data: bytes) -> list: # This creates a list of data blocks.
	print("math.ceil(len(data)/16) == "+str(math.ceil(len(data)/16)))
	blocks = [data[i:i+16] for i in range(0,math.ceil(len(data)/16)*16,16)] # Split into blocks.
	print("blocks == "+str(blocks))
	# Then we should pad the very last block.
	assert all([len(x)<=16 for x in blocks]) # Sanity checking
	if len(blocks[-1]) < 16:
		# pad the last block, because data length is not a multiple of 16 (in bytes).
		blocks[-1] = pad_plain_text(blocks[-1], 16)
		assert len(blocks[-1]) == 16 # Sanity checking.
	return blocks

def encrypt(data: bytes, key: bytes, mode="ECB", encryption=True) -> bytes: # This is the main encryption function. Default to the electronic code book encryption mode. (ECB is the WEAKEST!!!) encryption=True means that we are encrypting and encryption=False means that we are decrypting.
	# Now get the appropriate AES version.
	version = get_aes_ver_from_key(key)
	# Now run the key expansion.
	num_rounds, expanded_key, reverse_keys = key_expansion(key, version) # Use the 192 bit version instead of the 128
	print_keys(expanded_key)
	if mode == "ECB": # Electronic code book mode.
		# Now go over the data blocks.
		data_blocks = split_data_blocks(data)
		# encrypt each data block separately.
		# def encrypt_state(expanded_key: list, plaintext: bytes, num_rounds: int, W_list: list) -> bytes:
		# encrypt_state(expanded_key, example_plaintext, num_rounds, expanded_key)
		orig_expanded_key = copy.deepcopy(expanded_key)
		if encryption:

			encrypted_data_blocks = [encrypt_state(expanded_key, block, num_rounds, expanded_key) for block in data_blocks] # Encrypt each block.
		else:
			# Decryption
			encrypted_data_blocks = [decrypt_state(expanded_key, block, num_rounds, expanded_key) for block in data_blocks] # Encrypt each block.
		assert orig_expanded_key == expanded_key # Check for in-place modification. This should not change.
		# Join data blocks.
		encrypted_as_hex = ''.join(encrypted_data_blocks)
		# Convert to bytes.
		encrypted = bytes.fromhex(encrypted_as_hex)
		# Sanity check.
		#assert len(encrypted) == 16 # Should be the size of the "state" matrix.
		return encrypted
	return # Stub for now

def decrypt(encrypted: bytes, key: bytes, mode="ECB") -> bytes:
	return encrypt(encrypted, key, mode=mode, encryption=False)

def print_keys(keys: list) -> list:
	print("="*30)
	for key_mat in keys:
		stuff = print_hex(key_mat)
		print(stuff)
	print("="*30)
	return

def main():
	run_tests() # Sanity tests.
	return 0

if __name__=="__main__":

	exit(main())