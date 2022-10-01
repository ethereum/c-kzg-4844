import atexit
import ckzg
import random
import ssz

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
MAX_BLOBS_PER_BLOCK = 16

blobs_sedes = ssz.List(ssz.Vector(ssz.uint256, BLOB_SIZE), MAX_BLOBS_PER_BLOCK)
kzg_commitments_sedes = ssz.List(ssz.bytes48, MAX_BLOBS_PER_BLOCK)

# Commit to a few random blobs
num_blobs = 3
blobs = [ckzg.BLSFieldElements(BLOB_SIZE) for _ in range(num_blobs)]
for i in range(num_blobs):
    for j in range(BLOB_SIZE):
        blobs[i][j] = fr_from_int(random.randrange(0, 2**256))
kzg_commitments = [ckzg.blob_to_kzg_commitment(blob.cast(), ts) for blob in blobs]

# Compute polynomial commitments for these blobs
# We don't follow the spec exactly to get the hash, but it shouldn't matter since it's random data

blobs_as_ints = [[int_from_fr(frs[i]) for i in range(BLOB_SIZE)] for frs in blobs]
kzg_commitments_as_bytes = []
for c in kzg_commitments:
    a = ckzg.bytes(48)
    ckzg.bytes_from_G1(a.cast(), c)
    b = [a[i] for i in range(48)]
    kzg_commitments_as_bytes.append(bytearray(b))

encoded_blobs = ssz.encode(blobs_as_ints, blobs_sedes)
encoded_commitments = ssz.encode(kzg_commitments_as_bytes, kzg_commitments_sedes)
hashed = ssz.hash.hashlib.sha256(encoded_blobs + encoded_commitments).digest()
h = ckzg.bytes(len(hashed))
for i, byte in enumerate(hashed):
    h[i] = byte

r = ckzg.bytes_to_bls_field(h.cast())
r_powers = ckzg.BLSFieldElements(len(kzg_commitments))
ckzg.compute_powers(r_powers.cast(), r, len(kzg_commitments))

values = ckzg.BLSFieldElements(len(r_powers))

# ckzg.vector_lincomb(values.cast(), blobs

#     aggregated_poly = Polynomial(vector_lincomb(blobs, r_powers))
#
#     # Compute commitment to aggregated polynomial
#     aggregated_poly_commitment = KZGCommitment(g1_lincomb(kzg_commitments, r_powers))
#
#     return aggregated_poly, aggregated_poly_commitment


print('Tests passed')

def cleanup():
    ckzg.free_trusted_setup(ts)

atexit.register(cleanup)
