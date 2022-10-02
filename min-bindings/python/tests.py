import ckzg
import random
import ssz

# Simple test of bytes_to_bls_field

bs = (329).to_bytes(32, "little")
assert 329 == ckzg.int_from_bls_field(ckzg.bytes_to_bls_field(bs))

# Simple test of compute_powers

x = 32930439
n = 11

powers = ckzg.compute_powers(ckzg.bytes_to_bls_field(x.to_bytes(32, "little")), n)

p_check = 1
for p in powers:
    assert p_check == ckzg.int_from_bls_field(p)
    p_check *= x
    p_check %= 2**256

# Commit to a few random blobs

BLOB_SIZE = 4096
MAX_BLOBS_PER_BLOCK = 16

blobs_sedes = ssz.List(ssz.Vector(ssz.uint256, BLOB_SIZE), MAX_BLOBS_PER_BLOCK)
kzg_commitments_sedes = ssz.List(ssz.bytes48, MAX_BLOBS_PER_BLOCK)

blobs = [[ckzg.bytes_to_bls_field(random.randbytes(32)) for _ in range(BLOB_SIZE)] for _ in range(3)]

ts = ckzg.load_trusted_setup("../../src/trusted_setup.txt")

kzg_commitments = [ckzg.blob_to_kzg_commitment(blob, ts) for blob in blobs]

# Compute polynomial commitments for these blobs
# We don't follow the spec exactly to get the hash, but it shouldn't matter since it's random data

encoded_blobs = ssz.encode([[ckzg.int_from_bls_field(fr) for fr in blob] for blob in blobs], blobs_sedes)
encoded_commitments = ssz.encode([ckzg.bytes_from_g1(c) for c in kzg_commitments], kzg_commitments_sedes)
hashed = ssz.hash.hashlib.sha256(encoded_blobs + encoded_commitments).digest()

r = ckzg.bytes_to_bls_field(hashed)
r_powers = ckzg.compute_powers(r, len(blobs))

values = ckzg.vector_lincomb(blobs, r_powers)

aggregated_poly = ckzg.alloc_polynomial(values)

aggregated_poly_commitment = ckzg.g1_lincomb(kzg_commitments, r_powers)

# Compute proof

print('Tests passed')
