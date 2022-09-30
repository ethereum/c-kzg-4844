import atexit
import ckzg
import random

# Helper functions

def fr_from_int(x):
    r = []
    while x > 0:
        r.append(x % 2**64)
        x //= 2**64
    assert len(r) <= 4
    while len(r) < 4:
        r.append(0)
    return ckzg.BLSFieldElement_from_uint64s(tuple(r))

def int_from_fr(fr):
    digits = ckzg.uint64s_from_BLSFieldElement(fr)
    res, mult = 0, 1
    for x in digits:
        res += mult * x
        mult *= 2**64
    return res

def poly_from_values(values):
    ret, pptr = ckzg.alloc_polynomial(len(values))
    assert ret == 0
    p = ckzg.PolynomialEvalFormPtr_frompointer(pptr).value()
    pvalues = ckzg.BLSFieldElements_frompointer(p.values)
    for i, c in enumerate(values):
        pvalues[i] = fr_from_int(c)
    return p

# Simple test of compute_powers

x = 32930439
n = 11
p = 1

powers = ckzg.BLSFieldElements(n)
ckzg.compute_powers(powers.cast(), fr_from_int(x), n)

for i in range(n):
    assert p == int_from_fr(powers[i])
    p *= x
    p %= 2**256

# Load a trusted setup

ret, ts = ckzg.load_trusted_setup("../../src/trusted_setup.txt")
assert ret == 0

BLOB_SIZE = 4096

# Commit to a blob

blob = ckzg.BLSFieldElements(BLOB_SIZE)
for i in range(BLOB_SIZE):
    blob[i] = fr_from_int(random.randrange(0, 2**256))
commitment = ckzg.blob_to_kzg_commitment(blob.cast(), ts)

print('Tests passed')

def cleanup():
    ckzg.free_trusted_setup(ts)

atexit.register(cleanup)
