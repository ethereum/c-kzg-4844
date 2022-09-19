import atexit
import ckzg
import kzg_proofs

def int_from_uint64s(digits):
    """Convert a 4-tuple of base64 digits to the int it denotes"""
    res, mult = 0, 1
    for x in digits:
        res += mult * x
        mult *= 2 ** 64
    return res

def fr_from_int(x):
    r = []
    while x > 0:
        r.append(x % 2**64)
        x //= 2**64
    assert len(r) <= 4
    while len(r) < 4:
        r.append(0)
    return ckzg.fr_from_uint64s(tuple(r))

def fr_to_int(fr):
    return int_from_uint64s(ckzg.fr_to_uint64s(fr))

import random

polynomial = [random.randint(0, 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001) for i in range(1024)]
n = len(polynomial)

secret_value = 1927409816240961209460912649124348975783457236447839525141982745761361378419

cfa = ckzg.frArray(len(polynomial))
for i, c in enumerate(polynomial):
    cfa[i] = fr_from_int(c)

# Build the polynomial

ret, p = ckzg.new_poly_with_coeffs(cfa.cast(), len(polynomial))
assert ret == ckzg.C_KZG_OK

# Build a trusted setup with an arbitrary secret s
# and max scale 4 (so 16 secret values)

max_scale = n.bit_length() - 1

ret, fs = ckzg.new_fft_settings(max_scale)
assert ret == 0

sa = ckzg.byteArray(32)
for i, c in enumerate(secret_value.to_bytes(32, "little")):
    sa[i] = c

ret, secret_s = ckzg.blst_scalar_from_le_bytes(sa.cast(), 32)
assert ret == 1

test_secret = ckzg.fr_from_scalar(secret_s)
assert fr_to_int(test_secret) == secret_value


num_secrets = 2 ** max_scale

g1s = ckzg.g1Array(num_secrets)
g2s = ckzg.g2Array(num_secrets)

ckzg.generate_trusted_setup(g1s.cast(), g2s.cast(), secret_s, num_secrets)

ret, ks = ckzg.new_kzg_settings(g1s.cast(), g2s.cast(), num_secrets, fs)
assert ret == 0

# Compute the Lagrange form of our polynomial in this setup

ret, p_l = ckzg.new_poly_l_from_poly(p, ks)
assert ret == 0

x = 832877253762587406983796272890571809375809175809315245
fr_x = fr_from_int(x)
assert fr_to_int(fr_x) == x

ret, y_l = ckzg.eval_poly_l(p_l, fr_x, fs)
assert ret == 0

y = ckzg.eval_poly(p, fr_x)
assert ckzg.fr_equal(y, y_l)

y_p = kzg_proofs.eval_poly_at(polynomial, x)
assert fr_to_int(y) == y_p

# Commit to the polynomial, in both Lagrange and coefficient form
# The commitment should be the same

ret, commitment = ckzg.commit_to_poly(p, ks)
assert ret == 0
ret, commitment_l = ckzg.commit_to_poly_l(p_l, ks)
assert ret == 0
assert ckzg.g1_equal(commitment, commitment_l)

# Compute proof at an arbitrary point (for both forms)

ret, π = ckzg.compute_proof_single(p, fr_x, ks)
assert ret == 0
ret, v = ckzg.eval_poly_l(p_l, fr_x, fs)
assert ret == 0
ret, π_l = ckzg.compute_proof_single_l(p_l, fr_x, v, ks)
assert ret == 0

# Compute proof using py_ecc

pyecc_setup = kzg_proofs.generate_setup(secret_value, n)

pyecc_commitment = kzg_proofs.commit_to_poly(polynomial, pyecc_setup)
pyecc_proof = kzg_proofs.compute_proof_single(polynomial, x, pyecc_setup)
assert kzg_proofs.check_proof_single(pyecc_commitment, pyecc_proof, x, y_p, pyecc_setup)

from py_ecc.bls.point_compression import compress_G1

pyecc_commitment_compressed = compress_G1(pyecc_commitment)
pyecc_proof_compressed = compress_G1(pyecc_proof)

commitment_compressed = ckzg.byteArray(48)

ckzg.blst_p1_compress(commitment_compressed.cast(), commitment)

commitment_compressed = bytes([commitment_compressed[i] for i in range(48)])
assert commitment_compressed == pyecc_commitment_compressed.to_bytes(48, "big")


proof_compressed = ckzg.byteArray(48)

ckzg.blst_p1_compress(proof_compressed.cast(), π)

proof_compressed = bytes([proof_compressed[i] for i in range(48)])
assert proof_compressed == pyecc_proof_compressed.to_bytes(48, "big")

# Check the proofs using the commitments

ret, res = ckzg.check_proof_single(commitment, π, fr_x, v, ks)
assert ret == 0
assert res

ret, res = ckzg.check_proof_single(commitment_l, π_l, fr_x, v, ks)
assert ret == 0
assert res

# Check the proof fails with the wrong value

w = ckzg.fr_add(v, ckzg.fr_one)
ret, res = ckzg.check_proof_single(commitment_l, π_l, fr_x, w, ks)
assert ret == 0
assert not res

print("All tests passed.")

# We need to manually free the C allocated arrays
# Use atexit so this file can be loaded interactively before freeing
def cleanup():
    ckzg.free_poly(p)
    ckzg.free_poly_l(p_l)
    ckzg.free_fft_settings(fs)
    ckzg.free_kzg_settings(ks)
atexit.register(cleanup)
