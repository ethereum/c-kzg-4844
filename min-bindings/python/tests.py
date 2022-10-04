import ckzg
import random
import ssz

# Simple test of bytes_to_bls_field

bs = (329).to_bytes(32, "little")
assert 329 == ckzg.int_from_bls_field(ckzg.bytes_to_bls_field(bs))

del bs

# Simple test of compute_powers

x = 32930439
n = 11

powers = ckzg.compute_powers(ckzg.bytes_to_bls_field(x.to_bytes(32, "little")), n)

p_check = 1
for p in powers:
    assert p_check == ckzg.int_from_bls_field(p)
    p_check *= x
    p_check %= 2**256

del x, n, powers, p_check

# Simple test of polynomial evaluation

ts = ckzg.load_trusted_setup("tiny_trusted_setup.txt")

lvals = [239807672958224171024, 239807672958224171018,
         3465144826073652318776269530687742778510060141723586134027,
         52435875175126190475982595682112313518914282969839895044573213904131443392524]

def int_to_bls_field(x):
    return ckzg.bytes_to_bls_field(x.to_bytes(32, "little"))

poly = ckzg.alloc_polynomial(tuple(map(int_to_bls_field, lvals)))

y = ckzg.evaluate_polynomial_in_evaluation_form(poly, int_to_bls_field(2), ts)

assert ckzg.int_from_bls_field(y) == 239807672958224171036

# Commit to a few random blobs

BLOB_SIZE = 4096
MAX_BLOBS_PER_BLOCK = 16

blobs_sedes = ssz.List(ssz.Vector(ssz.uint256, BLOB_SIZE), MAX_BLOBS_PER_BLOCK)
kzg_commitments_sedes = ssz.List(ssz.bytes48, MAX_BLOBS_PER_BLOCK)

blobs = [
  [ckzg.bytes_to_bls_field(random.randbytes(32)) for _ in range(BLOB_SIZE)]
  for _ in range(3)
]

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

simple_commitment = ckzg.blob_to_kzg_commitment(values, ts)

# Compute proof

values_sedes = ssz.List(ssz.uint256, MAX_BLOBS_PER_BLOCK)

encoded_polynomial = ssz.encode([ckzg.int_from_bls_field(fr) for fr in values], values_sedes)
encoded_polynomial_length = ssz.encode(len(values), ssz.uint64)
encoded_commitment = ssz.encode(ckzg.bytes_from_g1(aggregated_poly_commitment), ssz.bytes48)
hashed_polynomial_and_commitment = ssz.hash.hashlib.sha256(
        encoded_polynomial + encoded_polynomial_length + encoded_commitment).digest()

x = ckzg.bytes_to_bls_field(hashed_polynomial_and_commitment)

proof = ckzg.compute_kzg_proof(aggregated_poly, x, ts)

# Verify proof

y = ckzg.evaluate_polynomial_in_evaluation_form(aggregated_poly, x, ts)

assert ckzg.bytes_from_g1(simple_commitment) == ckzg.bytes_from_g1(aggregated_poly_commitment)

assert ckzg.verify_kzg_proof(simple_commitment, x, y, proof, ts), 'Simple verification failed'

assert ckzg.verify_kzg_proof(aggregated_poly_commitment, x, y, proof, ts), 'Verification failed'

# Verification fails at wrong value

x2_bytes = random.randbytes(32)
while x2_bytes == hashed_polynomial_and_commitment:
    x2_bytes = random.randbytes(32)
x2 = ckzg.bytes_to_bls_field(x2_bytes)

y2 = ckzg.evaluate_polynomial_in_evaluation_form(aggregated_poly, x2, ts)

assert not ckzg.verify_kzg_proof(aggregated_poly_commitment, x, y2, proof, ts), 'Verification should fail'

print('Tests passed')
