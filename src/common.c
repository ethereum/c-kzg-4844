/*
 * Copyright 2024 Benjamin Edgington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common.h"

////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory Allocation
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Wrapped malloc() that reports failures to allocate.
 *
 * @remark Will return C_KZG_BADARGS if the requested size is zero.
 *
 * @param[out] out  Pointer to the allocated space
 * @param[in]  size The number of bytes to be allocated
 */
C_KZG_RET c_kzg_malloc(void **out, size_t size) {
    *out = NULL;
    if (size == 0) return C_KZG_BADARGS;
    *out = malloc(size);
    return *out != NULL ? C_KZG_OK : C_KZG_MALLOC;
}

/**
 * Wrapped calloc() that reports failures to allocate.
 *
 * @param[out] out   Pointer to the allocated space
 * @param[in]  count The number of elements
 * @param[in]  size  The size of each element
 *
 * @remark Will return C_KZG_BADARGS if the requested size is zero.
 */
C_KZG_RET c_kzg_calloc(void **out, size_t count, size_t size) {
    *out = NULL;
    if (count == 0 || size == 0) return C_KZG_BADARGS;
    *out = calloc(count, size);
    return *out != NULL ? C_KZG_OK : C_KZG_MALLOC;
}

/**
 * Allocate memory for an array of G1 group elements.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of G1 elements to be allocated
 *
 * @remark Free the space later using c_kzg_free().
 */
C_KZG_RET new_g1_array(g1_t **x, size_t n) {
    return c_kzg_calloc((void **)x, n, sizeof(g1_t));
}

/**
 * Allocate memory for an array of G2 group elements.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of G2 elements to be allocated
 *
 * @remark Free the space later using c_kzg_free().
 */
C_KZG_RET new_g2_array(g2_t **x, size_t n) {
    return c_kzg_calloc((void **)x, n, sizeof(g2_t));
}

/**
 * Allocate memory for an array of field elements.
 *
 * @param[out] x Pointer to the allocated space
 * @param[in]  n The number of field elements to be allocated
 *
 * @remark Free the space later using c_kzg_free().
 */
C_KZG_RET new_fr_array(fr_t **x, size_t n) {
    return c_kzg_calloc((void **)x, n, sizeof(fr_t));
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// General Helper Functions
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Utility function to test whether the argument is a power of two.
 *
 * @param[in] n The number to test
 *
 * @return True if `n` is zero or a power of two, otherwise false.
 *
 * @remark This method returns true for is_power_of_two(0) which is a bit weird, but not an issue in
 * the contexts in which we use it.
 *
 */
bool is_power_of_two(uint64_t n) {
    return (n & (n - 1)) == 0;
}

/**
 * Calculate log base two of a power of two.
 *
 * @param[in] n The power of two
 *
 * @return The log base two of n.
 *
 * @remark In other words, the bit index of the one bit.
 * @remark Works only for n a power of two, and only for n up to 2^31.
 * @remark Not the fastest implementation, but it doesn't need to be fast.
 */
int log2_pow2(uint32_t n) {
    int position = 0;
    while (n >>= 1)
        position++;
    return position;
}

/**
 * Reverse the bit order in a 32-bit integer.
 *
 * @param[in]   n   The integer to be reversed
 *
 * @return An integer with the bits of `n` reversed.
 */
uint32_t reverse_bits(uint32_t n) {
    uint32_t result = 0;
    for (int i = 0; i < 32; ++i) {
        result <<= 1;
        result |= (n & 1);
        n >>= 1;
    }
    return result;
}

/**
 * Reorder an array in reverse bit order of its indices.
 *
 * @param[in,out] values The array, which is re-ordered in-place
 * @param[in]     size   The size in bytes of an element of the array
 * @param[in]     n      The length of the array, must be a power of two
 *                       strictly greater than 1 and less than 2^32.
 *
 * @remark Operates in-place on the array.
 * @remark Can handle arrays of any type: provide the element size in `size`.
 * @remark This means that `input[n] == output[n']`, where input and output denote the input and
 * output array and n' is obtained from n by bit-reversing n. As opposed to reverse_bits, this
 * bit-reversal operates on log2(n)-bit numbers.
 */
C_KZG_RET bit_reversal_permutation(void *values, size_t size, uint64_t n) {
    C_KZG_RET ret;
    byte *tmp = NULL;
    byte *v = values;

    /* Some sanity checks */
    if (n < 2 || n >= UINT32_MAX || !is_power_of_two(n)) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Scratch space for swapping an entry of the values array */
    ret = c_kzg_malloc((void **)&tmp, size);
    if (ret != C_KZG_OK) goto out;

    /* Reorder elements */
    int unused_bit_len = 32 - log2_pow2(n);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t r = reverse_bits(i) >> unused_bit_len;
        if (r > i) {
            /* Swap the two elements */
            memcpy(tmp, v + (i * size), size);
            memcpy(v + (i * size), v + (r * size), size);
            memcpy(v + (r * size), tmp, size);
        }
    }

out:
    c_kzg_free(tmp);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Conversion and Validation
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Serialize a G1 group element into bytes.
 *
 * @param[out] out A 48-byte array to store the serialized G1 element
 * @param[in]  in  The G1 element to be serialized
 */
void bytes_from_g1(Bytes48 *out, const g1_t *in) {
    blst_p1_compress(out->bytes, in);
}

/**
 * Serialize a BLS field element into bytes.
 *
 * @param[out] out A 32-byte array to store the serialized field element
 * @param[in] in The field element to be serialized
 */
void bytes_from_bls_field(Bytes32 *out, const fr_t *in) {
    blst_scalar s;
    blst_scalar_from_fr(&s, in);
    blst_bendian_from_scalar(out->bytes, &s);
}

/**
 * Serialize a 64-bit unsigned integer into bytes.
 *
 * @param[out] out An 8-byte array to store the serialized integer
 * @param[in]  n   The integer to be serialized
 *
 * @remark The output format is big-endian.
 */
void bytes_from_uint64(uint8_t out[8], uint64_t n) {
    for (int i = 7; i >= 0; i--) {
        out[i] = n & 0xFF;
        n >>= 8;
    }
}

/**
 * Perform BLS validation required by the types KZGProof and KZGCommitment.
 *
 * @param[out]  out The output g1 point
 * @param[in]   b   The proof/commitment bytes
 *
 * @remark This function deviates from the spec because it returns (via an output argument) the g1
 * point. This way is more efficient (faster) but the function name is a bit misleading.
 */
static C_KZG_RET validate_kzg_g1(g1_t *out, const Bytes48 *b) {
    blst_p1_affine p1_affine;

    /* Convert the bytes to a p1 point */
    /* The uncompress routine checks that the point is on the curve */
    if (blst_p1_uncompress(&p1_affine, b->bytes) != BLST_SUCCESS) return C_KZG_BADARGS;
    blst_p1_from_affine(out, &p1_affine);

    /* The point at infinity is accepted! */
    if (blst_p1_is_inf(out)) return C_KZG_OK;
    /* The point must be on the right subgroup */
    if (!blst_p1_in_g1(out)) return C_KZG_BADARGS;

    return C_KZG_OK;
}

/**
 * Convert untrusted bytes to a trusted and validated BLS scalar field element.
 *
 * @param[out] out The field element to store the deserialized data
 * @param[in]  b   A 32-byte array containing the serialized field element
 */
C_KZG_RET bytes_to_bls_field(fr_t *out, const Bytes32 *b) {
    blst_scalar tmp;
    blst_scalar_from_bendian(&tmp, b->bytes);
    if (!blst_scalar_fr_check(&tmp)) return C_KZG_BADARGS;
    blst_fr_from_scalar(out, &tmp);
    return C_KZG_OK;
}

/**
 * Convert untrusted bytes into a trusted and validated KZGCommitment.
 *
 * @param[out]  out The output commitment
 * @param[in]   b   The commitment bytes
 */
C_KZG_RET bytes_to_kzg_commitment(g1_t *out, const Bytes48 *b) {
    return validate_kzg_g1(out, b);
}

/**
 * Convert untrusted bytes into a trusted and validated KZGProof.
 *
 * @param[out]  out The output proof
 * @param[in]   b   The proof bytes
 */
C_KZG_RET bytes_to_kzg_proof(g1_t *out, const Bytes48 *b) {
    return validate_kzg_g1(out, b);
}

/**
 * Create a field element from a single 64-bit unsigned integer.
 *
 * @param[out] out The field element equivalent of `n`
 * @param[in]  n   The 64-bit integer to be converted
 *
 * @remark This can only generate a tiny fraction of possible field elements,
 *         and is mostly useful for testing.
 */
void fr_from_uint64(fr_t *out, uint64_t n) {
    uint64_t vals[] = {n, 0, 0, 0};
    blst_fr_from_uint64(out, vals);
}

/**
 * Map bytes to a BLS field element.
 *
 * @param[out] out The field element to store the result
 * @param[in]  b   A 32-byte array containing the input
 */
void hash_to_bls_field(fr_t *out, const Bytes32 *b) {
    blst_scalar tmp;
    blst_scalar_from_bendian(&tmp, b->bytes);
    blst_fr_from_scalar(out, &tmp);
}

/**
 * Deserialize a blob (array of bytes) into a polynomial (array of field elements).
 *
 * @param[out]  p           The output polynomial (array of field elements)
 * @param[in]   blob        The blob (an array of bytes)
 * @param[in]   num_fields  The number of field elements in the blob
 */
C_KZG_RET blob_to_polynomial(fr_t *p, const uint8_t *blob, size_t num_fields) {
    C_KZG_RET ret;
    for (size_t i = 0; i < num_fields; i++) {
        ret = bytes_to_bls_field(&p[i], (Bytes32 *)&blob[i * BYTES_PER_FIELD_ELEMENT]);
        if (ret != C_KZG_OK) return ret;
    }
    return C_KZG_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Field Operations
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Test whether two field elements are equal.
 *
 * @param[in]   a   The first element
 * @param[in]   b   The second element
 *
 * @retval true     The two elements are equal.
 * @retval false    The two elements are not equal.
 */
bool fr_equal(const fr_t *a, const fr_t *b) {
    uint64_t _a[4], _b[4];
    blst_uint64_from_fr(_a, a);
    blst_uint64_from_fr(_b, b);
    return _a[0] == _b[0] && _a[1] == _b[1] && _a[2] == _b[2] && _a[3] == _b[3];
}

/**
 * Test whether the operand is one in the finite field.
 *
 * @param[in] p The field element to be checked
 *
 * @retval true  The element is one
 * @retval false The element is not one
 */
bool fr_is_one(const fr_t *p) {
    uint64_t a[4];
    blst_uint64_from_fr(a, p);
    return a[0] == 1 && a[1] == 0 && a[2] == 0 && a[3] == 0;
}

/**
 * Divide a field element by another.
 *
 * @param[out] out `a` divided by `b` in the field
 * @param[in]  a   The dividend
 * @param[in]  b   The divisor
 *
 * @remark The behavior for `b == 0` is unspecified.
 * @remark This function supports in-place computation.
 */
void fr_div(fr_t *out, const fr_t *a, const fr_t *b) {
    blst_fr tmp;
    blst_fr_eucl_inverse(&tmp, b);
    blst_fr_mul(out, a, &tmp);
}

/**
 * Exponentiation of a field element.
 *
 * Uses square and multiply for log(n) performance.
 *
 * @param[out] out `a` raised to the power of `n`
 * @param[in]  a   The field element to be exponentiated
 * @param[in]  n   The exponent
 *
 * @remark A 64-bit exponent is sufficient for our needs here.
 * @remark This function does support in-place computation.
 */
void fr_pow(fr_t *out, const fr_t *a, uint64_t n) {
    fr_t tmp = *a;
    *out = FR_ONE;

    while (true) {
        if (n & 1) {
            blst_fr_mul(out, out, &tmp);
        }
        if ((n >>= 1) == 0) break;
        blst_fr_sqr(&tmp, &tmp);
    }
}

/**
 * Compute and return [ x^0, x^1, ..., x^{n-1} ].
 *
 * @param[out]  out The array to store the powers
 * @param[in]   x   The field element to raise to powers
 * @param[in]   n   The number of powers to compute
 *
 * @remark `out` is left untouched if `n == 0`.
 */
void compute_powers(fr_t *out, const fr_t *x, uint64_t n) {
    fr_t current_power = FR_ONE;
    for (uint64_t i = 0; i < n; i++) {
        out[i] = current_power;
        blst_fr_mul(&current_power, &current_power, x);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Point Operations
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Subtraction of G1 group elements.
 *
 * @param[out] out `a - b`
 * @param[in]  a   A G1 group element
 * @param[in]  b   The G1 group element to be subtracted
 */
void g1_sub(g1_t *out, const g1_t *a, const g1_t *b) {
    g1_t bneg = *b;
    blst_p1_cneg(&bneg, true);
    blst_p1_add_or_double(out, a, &bneg);
}

/**
 * Multiply a G1 group element by a field element.
 *
 * @param[out] out  `a * b`
 * @param[in]  a    The G1 group element
 * @param[in]  b    The multiplier
 */
void g1_mul(g1_t *out, const g1_t *a, const fr_t *b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    blst_p1_mult(out, a, s.b, BITS_PER_FIELD_ELEMENT);
}

/**
 * Perform pairings and test whether the outcomes are equal in G_T.
 *
 * Tests whether `e(a1, a2) == e(b1, b2)`.
 *
 * @param[in] a1 A G1 group point for the first pairing
 * @param[in] a2 A G2 group point for the first pairing
 * @param[in] b1 A G1 group point for the second pairing
 * @param[in] b2 A G2 group point for the second pairing
 *
 * @retval true  The pairings were equal
 * @retval false The pairings were not equal
 */
bool pairings_verify(const g1_t *a1, const g2_t *a2, const g1_t *b1, const g2_t *b2) {
    blst_fp12 loop0, loop1, gt_point;
    blst_p1_affine aa1, bb1;
    blst_p2_affine aa2, bb2;

    /*
     * As an optimisation, we want to invert one of the pairings,
     * so we negate one of the points.
     */
    g1_t a1neg = *a1;
    blst_p1_cneg(&a1neg, true);

    blst_p1_to_affine(&aa1, &a1neg);
    blst_p1_to_affine(&bb1, b1);
    blst_p2_to_affine(&aa2, a2);
    blst_p2_to_affine(&bb2, b2);

    blst_miller_loop(&loop0, &aa2, &aa1);
    blst_miller_loop(&loop1, &bb2, &bb1);

    blst_fp12_mul(&gt_point, &loop0, &loop1);
    blst_final_exp(&gt_point, &gt_point);

    return blst_fp12_is_one(&gt_point);
}

/**
 * Calculate a linear combination of G1 group elements.
 *
 * Calculates `[coeffs_0]p_0 + [coeffs_1]p_1 + ... + [coeffs_n]p_n`
 * where `n` is `len - 1`.
 *
 * This function computes the result naively without using Pippenger's algorithm.
 */
void g1_lincomb_naive(g1_t *out, const g1_t *p, const fr_t *coeffs, uint64_t len) {
    g1_t tmp;
    *out = G1_IDENTITY;
    for (uint64_t i = 0; i < len; i++) {
        g1_mul(&tmp, &p[i], &coeffs[i]);
        blst_p1_add_or_double(out, out, &tmp);
    }
}

/**
 * Calculate a linear combination of G1 group elements.
 *
 * Calculates `[coeffs_0]p_0 + [coeffs_1]p_1 + ... + [coeffs_n]p_n` where `n` is `len - 1`.
 *
 * @param[out] out    The resulting sum-product
 * @param[in]  p      Array of G1 group elements, length `len`
 * @param[in]  coeffs Array of field elements, length `len`
 * @param[in]  len    The number of group/field elements
 *
 * @remark This function CAN be called with the point at infinity in `p`.
 * @remark While this function is significantly faster than g1_lincomb_naive(), we refrain from
 * using it in security-critical places (like verification) because the blst Pippenger code has not
 * been audited. In those critical places, we prefer using g1_lincomb_naive() which is much simpler.
 *
 * For the benefit of future generations (since blst has no documentation to speak of), there are
 * two ways to pass the arrays of scalars and points into blst_p1s_mult_pippenger().
 *
 * 1. Pass `points` as an array of pointers to the points, and pass `scalars` as an array of
 *    pointers to the scalars, each of length `len`.
 * 2. Pass an array where the first element is a pointer to the contiguous array of points and the
 *    second is null, and similarly for scalars.
 *
 * We do the second of these to save memory here.
 */
C_KZG_RET g1_lincomb_fast(g1_t *out, const g1_t *p, const fr_t *coeffs, size_t len) {
    C_KZG_RET ret;
    void *scratch = NULL;
    blst_p1 *p_filtered = NULL;
    blst_p1_affine *p_affine = NULL;
    blst_scalar *scalars = NULL;

    /* Tunable parameter: must be at least 2 since blst fails for 0 or 1 */
    const size_t min_length_threshold = 8;

    /* Use naive method if it's less than the threshold */
    if (len < min_length_threshold) {
        g1_lincomb_naive(out, p, coeffs, len);
        ret = C_KZG_OK;
        goto out;
    }

    /* Allocate space for arrays */
    ret = c_kzg_calloc((void **)&p_filtered, len, sizeof(blst_p1));
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_calloc((void **)&p_affine, len, sizeof(blst_p1_affine));
    if (ret != C_KZG_OK) goto out;
    ret = c_kzg_calloc((void **)&scalars, len, sizeof(blst_scalar));
    if (ret != C_KZG_OK) goto out;

    /* Allocate space for Pippenger scratch */
    size_t scratch_size = blst_p1s_mult_pippenger_scratch_sizeof(len);
    ret = c_kzg_malloc(&scratch, scratch_size);
    if (ret != C_KZG_OK) goto out;

    /* Transform the field elements to 256-bit scalars */
    for (size_t i = 0; i < len; i++) {
        blst_scalar_from_fr(&scalars[i], &coeffs[i]);
    }

    /* Filter out zero points: make a new list p_filtered that contains only non-zero points */
    size_t new_len = 0;
    for (size_t i = 0; i < len; i++) {
        if (!blst_p1_is_inf(&p[i])) {
            /* Copy valid points to the new position */
            p_filtered[new_len] = p[i];
            scalars[new_len] = scalars[i];
            new_len++;
        }
    }

    /* Check if the new length is fine */
    if (new_len < min_length_threshold) {
        /* We must use the original inputs */
        g1_lincomb_naive(out, p, coeffs, len);
        ret = C_KZG_OK;
        goto out;
    }

    /* Transform the points to affine representation */
    const blst_p1 *p_arg[2] = {p_filtered, NULL};
    blst_p1s_to_affine(p_affine, p_arg, new_len);

    /* Call the Pippenger implementation */
    const byte *scalars_arg[2] = {(byte *)scalars, NULL};
    const blst_p1_affine *points_arg[2] = {p_affine, NULL};
    blst_p1s_mult_pippenger(out, points_arg, new_len, scalars_arg, BITS_PER_FIELD_ELEMENT, scratch);
    ret = C_KZG_OK;

out:
    c_kzg_free(scratch);
    c_kzg_free(p_filtered);
    c_kzg_free(p_affine);
    c_kzg_free(scalars);
    return ret;
}

/**
 * Fast Fourier Transform.
 *
 * Recursively divide and conquer.
 *
 * @param[out] out          The results (length `n`)
 * @param[in]  in           The input data (length `n * stride`)
 * @param[in]  stride       The input data stride
 * @param[in]  roots        Roots of unity (length `n * roots_stride`)
 * @param[in]  roots_stride The stride interval among the roots of unity
 * @param[in]  n            Length of the FFT, must be a power of two
 */
static void fft_g1_fast(
    g1_t *out, const g1_t *in, uint64_t stride, const fr_t *roots, uint64_t roots_stride, uint64_t n
) {
    g1_t y_times_root;
    uint64_t half = n / 2;
    if (half > 0) { /* Tunable parameter */
        fft_g1_fast(out, in, stride * 2, roots, roots_stride * 2, half);
        fft_g1_fast(out + half, in + stride, stride * 2, roots, roots_stride * 2, half);
        for (uint64_t i = 0; i < half; i++) {
            /* If the point is infinity, we can skip the calculation */
            if (blst_p1_is_inf(&out[i + half])) {
                out[i + half] = out[i];
            } else {
                /* If the scalar is one, we can skip the multiplication */
                if (fr_is_one(&roots[i * roots_stride])) {
                    y_times_root = out[i + half];
                } else {
                    g1_mul(&y_times_root, &out[i + half], &roots[i * roots_stride]);
                }
                g1_sub(&out[i + half], &out[i], &y_times_root);
                blst_p1_add_or_double(&out[i], &out[i], &y_times_root);
            }
        }
    } else {
        *out = *in;
    }
}

/**
 * The entry point for forward FFT over G1 points.
 *
 * @param[out]  out The results (array of length n)
 * @param[in]   in  The input data (array of length n)
 * @param[in]   n   Length of the arrays
 * @param[in]   s   The trusted setup
 *
 * @remark The array lengths must be a power of two.
 * @remark Use ifft_g1() for inverse transformation.
 */
C_KZG_RET fft_g1(g1_t *out, const g1_t *in, size_t n, const KZGSettings *s) {
    /* Ensure the length is valid */
    if (n > s->max_width || !is_power_of_two(n)) {
        return C_KZG_BADARGS;
    }

    uint64_t stride = s->max_width / n;
    fft_g1_fast(out, in, 1, s->expanded_roots_of_unity, stride, n);

    return C_KZG_OK;
}

/**
 * The entry point for inverse FFT over G1 points.
 *
 * @param[out]  out The results (array of length n)
 * @param[in]   in  The input data (array of length n)
 * @param[in]   n   Length of the arrays
 * @param[in]   s   The trusted setup
 *
 * @remark The array lengths must be a power of two.
 * @remark Use fft_g1() for forward transformation.
 */
C_KZG_RET ifft_g1(g1_t *out, const g1_t *in, size_t n, const KZGSettings *s) {
    /* Ensure the length is valid */
    if (n > s->max_width || !is_power_of_two(n)) {
        return C_KZG_BADARGS;
    }

    uint64_t stride = s->max_width / n;
    fft_g1_fast(out, in, 1, s->reverse_roots_of_unity, stride, n);

    fr_t inv_len;
    fr_from_uint64(&inv_len, n);
    blst_fr_eucl_inverse(&inv_len, &inv_len);
    for (uint64_t i = 0; i < n; i++) {
        g1_mul(&out[i], &out[i], &inv_len);
    }

    return C_KZG_OK;
}
