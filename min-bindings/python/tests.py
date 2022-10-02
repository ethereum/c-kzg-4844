import ckzg
import random

# Simple test of bytes_to_bls_field

bs = (329).to_bytes(32, "little")
assert 329 == ckzg.int_from_BLSFieldElement(ckzg.bytes_to_bls_field(bs))

print('Tests passed')
