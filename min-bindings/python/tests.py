import atexit
import ckzg
import random
import ssz

# Simple test of compute_powers

x = 32930439
n = 11
p = 1

powers = ckzg.BLSFieldElements(n)
ckzg.compute_powers(powers.cast(), ckzg.blst_fr.from_int(x), n)

for i in range(n):
    assert p == int(powers[i])
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
blobs = [ckzg.BLSFieldElements(BLOB_SIZE) for _ in range(3)]
for i in range(len(blobs)):
    for j in range(BLOB_SIZE):
        blobs[i][j] = ckzg.blst_fr.from_int(random.randrange(0, 2**256))
kzg_commitments = [ckzg.blob_to_kzg_commitment(blob.cast(), ts) for blob in blobs]

# Compute polynomial commitments for these blobs
# We don't follow the spec exactly to get the hash, but it shouldn't matter since it's random data

blobs_as_ints = [[int(frs[i]) for i in range(BLOB_SIZE)] for frs in blobs]
kzg_commitments_as_bytes = []
for c in kzg_commitments:
    a = ckzg.bytes(48)
    ckzg.bytes_from_G1(a.cast(), c)
    b = [a[i] for i in range(48)]
    kzg_commitments_as_bytes.append(bytearray(b))

encoded_blobs = ssz.encode(blobs_as_ints, blobs_sedes)
encoded_commitments = ssz.encode(kzg_commitments_as_bytes, kzg_commitments_sedes)
hashed = ssz.hash.hashlib.sha256(encoded_blobs + encoded_commitments).digest()

h = ckzg.bytes.frompybytes(hashed)

r = ckzg.bytes_to_bls_field(h.cast())
r_powers = ckzg.BLSFieldElements(len(blobs))
ckzg.compute_powers(r_powers.cast(), r, len(blobs))

vectors = ckzg.BLSFieldVectors(len(blobs))
for i, v in enumerate(blobs):
    vectors[i] = v.cast()

ret, pptr = ckzg.alloc_polynomial(len(blobs))
assert ret == 0
aggregated_poly = ckzg.PolynomialEvalFormPtr_frompointer(pptr).value()

# ckzg.vector_lincomb(
#         aggregated_poly.values,
#         vectors.cast(),
#         r_powers.cast(),
#         len(blobs),
#         BLOB_SIZE)

#aggregated_poly_commitment =
#ckzg.g1_lincomb(kzg_commitments

#KZGCommitment(g1_lincomb(kzg_commitments, r_powers))

print('Tests passed')

def cleanup():
    ckzg.free_polynomial(pptr)
    ckzg.free_trusted_setup(ts)

atexit.register(cleanup)
