


# This is ripped straight from wikipedia.  https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
MIX_COL_DATA = '''db 13 53 45	8e 4d a1 bc	219 19 83 69	142 77 161 188
f2 0a 22 5c	9f dc 58 9d	242 10 34 92	159 220 88 157
01 01 01 01	01 01 01 01	1 1 1 1	1 1 1 1
c6 c6 c6 c6	c6 c6 c6 c6	198 198 198 198	198 198 198 198
d4 d4 d4 d5	d5 d5 d7 d6	212 212 212 213	213 213 215 214
2d 26 31 4c	4d 7e bd f8	45 38 49 76	77 126 189 248'''

def create_int_list(string: str) -> list: # Creates a list of integers from hex values separated by spaces.
    return [int(x, base=16) for x in string.split(" ")]

def parse_mix_col_testcases() -> list:
    # Creates a list of lists, where the first element in each list is the input list and the second element is the expected output list.
    out = []
    for line in MIX_COL_DATA.split("\n"):
        print("line == "+str(line))
        test_lists = line.split("	") # Split on tab character
        hex_input = test_lists[0]
        expected_output = test_lists[1]
        out.append([create_int_list(hex_input), create_int_list(expected_output)])
    # Sanity check. We test the test tool. :D
    print("out[0][0] == "+str(out[0][0]))
    print("out[0][1] == "+str(out[0][1]))
    assert out[0][0] == [0xdb,0x13,0x53,0x45]
    assert out[0][1] == [0x8e,0x4d,0xa1,0xbc]
    print("Generated the mix col testdata lists!!!")
    return out


MIX_COL_TESTS = parse_mix_col_testcases()

