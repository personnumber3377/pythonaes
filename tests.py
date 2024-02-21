

from main import * # This is used to import the functions which this file actually tests.
import rijndael

def run_tests() -> None:
	print("="*30)
	print("="*30)
	print("="*30)
	print("Now running tests!!!")
	test_transpose_mat()
	test_S()
	test_key_expansion()
	test_print_hex()
	test_s_box()
	# Test the reverse functions. If there is a function called f and an inverse function called F , then f(F(x)) = F(f(x)) = x
	test_shift()
	test_poly_mul()
	test_bits()
	test_poly_mod()
	test_mix_col()
	# After checking each function individually, now test the actual main encryption and decryption functions.
	test_enc_dec()
	test_enc_dec_192()
	test_enc_dec_256()
	print("All tests passed!!!")
	print("="*30)
	print("="*30)
	print("="*30)

	return

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

def test_S() -> None:
	assert rijndael.S_BOX[0x9a] == 0xb8

def test_key_expansion():
	string = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c"
	key = bytes([int(x, base=16) for x in string.split(" ")])
	_, expanded_key, _ = key_expansion(bytes(key), "128")
	print_hex(expanded_key)


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

def test_s_box() -> None:
	# Go through every index and check the reverse.
	for ind in range(256):
		orig_val = access_table(rijndael.S_BOX_MATRIX, ind)
		should_be_ind = access_table(rijndael.S_BOX_MATRIX_REV, orig_val)
		assert should_be_ind == ind
	print("test_s_box passed!")
	return


def test_poly_mul() -> None:
	a = 0b100
	b = 0b100
	res = poly_mul(a,b)
	assert res == 0b10000 # x**2 * x**2 == x**4
	
	# This example is ripped straight from the polynomial multiplication section of this pdf document: https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
	a = 87
	b = 131
	res = poly_mul(a,b)
	assert res == 193
	print("test_poly_mul passed")
	return


MAX_TEST_BITS = 0xffff

def test_bits() -> None:
	for i in range(1,MAX_TEST_BITS):
		assert bits(i) == len(bin(i))-2

def test_poly_mod() -> None:
	# Tests the polynomial modulo (remainder) in GF(2)
	pol1 = 0b100 # x**2
	pol2 = 0b10000 # x**4
	res = poly_mod(pol2, pol1)
	print("result of the polynomial modulo test: "+str(res))
	assert res == 0 # Polynomial remainder should be zero.
	#input()
	# A bit of a more complex testcase. This is taken from the pdf file multiplication section.
	pol1 = 11129
	pol2 = 283
	res = poly_mod(pol1, pol2)
	print("res == "+str(bin(res)))
	assert res == 193
	#input()
	return

def test_mix_col() -> None:
	# This is ripped straight from wikipedia.  https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
	tests = testdatahelper.MIX_COL_TESTS
	for x,y in tests: # x is input and y is expected output. We also test the reverse function.
		print("Now running another test.")
		print("Here is the expected: "+str(hex_list_to_str(y)))
		print("Here is the input: "+str(hex_list_to_str(x)))
		x_copy = copy.deepcopy(x)
		x = mix_col(x)
		assert x == y # Should be the expected output
		# Test the reverse function now. We should end up with the original input.
		x = rev_mix_column(y)
		print("Here is the output from the reverse function: "+str(hex_list_to_str(x)))
		assert x == x_copy
	print("test_mix_col passed!!!")
	return

def test_enc_dec_192() -> None:
	# Tests the 192-bit variant of the encryption and decryption algorithm.
	example_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
	key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
	print("Here is the key: "+str(key))
	num_rounds, expanded_key, reverse_keys = key_expansion(key, "192") # Use the 192 bit version instead of the 128
	print_keys(expanded_key)
	encrypted = encrypt_state(expanded_key, example_plaintext, num_rounds, expanded_key)
	print("Here is the encrypted data: "+str(encrypted))
	# Sanity check. It should be this.
	#assert encrypted == "69c4e0d86a7b0430d8cdb78070b4c55a" # This is the example vector from the pdf file. (192 bit version.)
	assert encrypted == "dda97ca4864cdfe06eaf70a0ec0d7191"
	# Now the encrypted data is in "encrypted". Now decrypting it, should return in the original plaintext.
	# First convert the encrypted stuff to bytes before decrypt_state.
	encrypted = bytes.fromhex(encrypted)
	decrypted = decrypt_state(expanded_key, encrypted, num_rounds, expanded_key)
	res = print_hex(decrypted)
	print("Here is the final decrypted result: "+str(res))
	assert res == "00112233445566778899aabbccddeeff"
	print("Done!")
	print("test_enc_dec passed!!!")
	return

def test_enc_dec_256() -> None:
	# This is the 256 bit key version test. This is quite important, because there are additional stuff which we need to do in the key_expansion function (see main.py key_expansion) for the 256 bit key case.
	# Tests the 192-bit variant of the encryption and decryption algorithm.
	print("Now testing test_enc_dec_256")
	example_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
	key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	print("Here is the key: "+str(key))
	num_rounds, expanded_key, reverse_keys = key_expansion(key, "256") # Use the 192 bit version instead of the 128
	print_keys(expanded_key)
	encrypted = encrypt_state(expanded_key, example_plaintext, num_rounds, expanded_key)
	print("Here is the encrypted data: "+str(encrypted))
	# Sanity check. It should be this.
	#assert encrypted == "69c4e0d86a7b0430d8cdb78070b4c55a" # This is the example vector from the pdf file. (192 bit version.)
	assert encrypted == "8ea2b7ca516745bfeafc49904b496089"
	# Now the encrypted data is in "encrypted". Now decrypting it, should return in the original plaintext.
	# First convert the encrypted stuff to bytes before decrypt_state.
	encrypted = bytes.fromhex(encrypted)
	decrypted = decrypt_state(expanded_key, encrypted, num_rounds, expanded_key)
	res = print_hex(decrypted)
	print("Here is the final decrypted result: "+str(res))
	assert res == "00112233445566778899aabbccddeeff"
	print("Done!")
	print("test_enc_dec_256 passed!!!")
	return


def test_enc_dec() -> None:
	encryption_key = "oofoof"
	num_rounds, expanded_key, reverse_keys = key_expansion(bytes(encryption_key, encoding="ascii"), "128")
	# 00112233445566778899aabbccddeeff
	# example_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
	#example_plaintext = bytes.fromhex("004488cc115599dd2266aaee3377bbff")
	example_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
	key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
	print("Here is the key: "+str(key))
	#key = bytes.fromhex("004488cc115599dd2266aaee3377bbff")
	num_rounds, expanded_key, reverse_keys = key_expansion(key, "128")
	print_keys(expanded_key)
	encrypted = encrypt_state(expanded_key, example_plaintext, num_rounds, expanded_key)
	print("Here is the encrypted data: "+str(encrypted))
	# Sanity check. It should be this.
	assert encrypted == "69c4e0d86a7b0430d8cdb78070b4c55a" # This is the example vector from the pdf file.

	#encrypted = "69c4e0d86a7b0430d8cdb78070b4c55a"
	# Now the encrypted data is in "encrypted". Now decrypting it, should return in the original plaintext.
	# First convert the encrypted stuff to bytes before decrypt_state.
	encrypted = bytes.fromhex(encrypted)

	# decrypted = decrypt_state(expanded_key, encrypted, num_rounds, expanded_key) # This was the old thing.
	#decrypted = decrypt_state(reverse_keys, encrypted, num_rounds, reverse_keys)
	# expanded_key

	decrypted = decrypt_state(expanded_key, encrypted, num_rounds, expanded_key)
	res = print_hex(decrypted)
	print("Here is the final decrypted result: "+str(res))
	assert res == "00112233445566778899aabbccddeeff"
	print("Done!")
	print("test_enc_dec passed!!!")
	return
