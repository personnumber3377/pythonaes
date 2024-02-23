from ocb import *
from main import *

def test_ntz() -> None:
    # 8 == 0b1000
    # 11 = 0b1011
    assert ntz(8) == 3
    assert ntz(11) == 0
    print("test_ntz passed!!!")
    return

def run_tests_ocb() -> None:
    test_ntz()
    return



