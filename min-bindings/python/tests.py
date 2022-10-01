import atexit
import ckzg
import random
import ssz

def int_from_fr(fr):
    digits = ckzg.uint64s_from_BLSFieldElement(fr)
    res, mult = 0, 1
    for x in digits:
        res += mult * x
        mult *= 2**64
    return res

# Simple test of bytes_to_bls_field

bs = (329).to_bytes(32, "little")
fr = ckzg.bytes_to_bls_field(bs)
assert int_from_fr(fr) == 329

print('Tests passed')

def cleanup():
    pass

atexit.register(cleanup)
