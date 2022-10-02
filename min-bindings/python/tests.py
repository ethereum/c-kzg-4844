import ckzg
import random

# Simple test of bytes_to_bls_field

bs = (329).to_bytes(32, "little")
assert 329 == ckzg.int_from_BLSFieldElement(ckzg.bytes_to_bls_field(bs))

# Simple test of compute_powers

x = 32930439
n = 11

powers = ckzg.compute_powers(ckzg.bytes_to_bls_field(x.to_bytes(32, "little")), n)

p_check = 1
for p in powers:
    assert p_check == ckzg.int_from_BLSFieldElement(p)
    p_check *= x
    p_check %= 2**256

print('Tests passed')
