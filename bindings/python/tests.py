import atexit
import ckzg

def int_from_uint64s(digits):
    """Convert a 4-tuple of base64 digits to the int it denotes"""
    res, mult = 0, 1
    for x in digits:
        res += mult * x
        mult *= 2 ** 64
    return res

def eval_poly(coeffs, x):
    """Evaluate a polynomial represented by a sequence of coefficients"""
    res, mult = 0, 1
    for c in coeffs:
        res += mult * c
        mult *= x
    return res

# Make some elements to be used as coefficients

c1 = ckzg.fr_from_uint64s((12,13,0,0))
c2 = ckzg.fr_from_uint64(2)
c3 = ckzg.fr_from_uint64s((1,0,0,0))
c4 = ckzg.fr_sub(c2, c3)

# A few sanity checks

assert ckzg.fr_is_one(c4)

assert ckzg.fr_equal(c3, c4)

# Create an array of the coefficients

coeffs = [c1, c2, c3, c4]
cfa = ckzg.frArray(len(coeffs))
for i, c in enumerate(coeffs):
    cfa[i] = c

# Build the polynomial

ret, pptr = ckzg.new_poly_with_coeffs(cfa.cast(), len(coeffs))
assert ret == 0

# Check one of its coefficients is as expected

p = ckzg.polyp_frompointer(pptr).value()
assert p.length == 4

pcoeffs = ckzg.frArray_frompointer(p.coeffs)
assert ckzg.fr_to_uint64s(pcoeffs[1]) == (2, 0, 0, 0)

# Build a trusted setup with an arbitrary secret s
# and max scale 4 (so 16 secret values)

max_scale = 4

ret, fs = ckzg.new_fft_settings(max_scale)
assert ret == 0

secret_s = ckzg.blst_scalar_from_uint64((29,3,1,4))

num_secrets = 2 ** max_scale

g1s = ckzg.g1Array(num_secrets)
g2s = ckzg.g2Array(num_secrets)

ckzg.generate_trusted_setup(g1s.cast(), g2s.cast(), secret_s, num_secrets)

ret, ks = ckzg.new_kzg_settings(g1s.cast(), g2s.cast(), num_secrets, fs)
assert ret == 0

# Compute the Lagrange form of our polynomial in this setup

ret, p_l = ckzg.new_poly_l_from_poly(p, ks)
assert ret == 0

# Check some evaluations at the point 2
# First, that Lagrange and coefficient form evaluations agree

ret, y_l = ckzg.eval_poly_l(p_l, c2, fs)
assert ret == 0

y = ckzg.eval_poly(p, c2)
assert ckzg.fr_equal(y, y_l)

# And that this agrees with a naive Python evaluation

def fr_to_int(fr):
    return int_from_uint64s(ckzg.fr_to_uint64s(fr))

py_coeffs = [fr_to_int(c) for c in coeffs]

y_p = eval_poly(py_coeffs, fr_to_int(c2))
assert fr_to_int(y) == y_p

# Commit to the polynomial, in both Lagrange and coefficient form
# The commitment should be the same

ret, commitment = ckzg.commit_to_poly(p, ks)
assert ret == 0
ret, commitment_l = ckzg.commit_to_poly_l(p_l, ks)
assert ret == 0
assert ckzg.g1_equal(commitment, commitment_l)

# Compute proof at an arbitrary point (for both forms)

x = ckzg.fr_from_uint64s((39, 100, 8, 0))
ret, π = ckzg.compute_proof_single(p, x, ks)
assert ret == 0
ret, v = ckzg.eval_poly_l(p_l, x, fs)
assert ret == 0
ret, π_l = ckzg.compute_proof_single_l(p_l, x, v, ks)
assert ret == 0

# Check the proofs using the commitments

ret, res = ckzg.check_proof_single(commitment, π, x, v, ks)
assert ret == 0
assert res

ret, res = ckzg.check_proof_single(commitment_l, π_l, x, v, ks)
assert ret == 0
assert res

# Check the proof fails with the wrong value

w = ckzg.fr_add(v, ckzg.fr_one)
ret, res = ckzg.check_proof_single(commitment_l, π_l, x, w, ks)
assert ret == 0
assert not res

print("All tests passed.")

# We need to manually free the C allocated arrays
# Use atexit so this file can be loaded interactively before freeing
def cleanup():
    ckzg.free_poly(pptr)
    ckzg.free_poly_l(p_l)
    ckzg.free_fft_settings(fs)
    ckzg.free_kzg_settings(ks)
atexit.register(cleanup)
