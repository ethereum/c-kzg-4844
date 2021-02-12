/*
 * Copyright 2021 Benjamin Edgington
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

/**
 *  @file fk20_proofs.c
 *
 * Implements amortised KZG proofs as per the [FK20
 * paper](https://github.com/khovratovich/Kate/blob/master/Kate_amortized.pdf).
 */

#include <stdlib.h> // free()
#include <string.h> // memcpy()
#include "fk20_proofs.h"
#include "fft_g1.h"
#include "c_kzg_util.h"

/**
 * Calculate log base two of a power of two.
 *
 * In other words, the bit index of the one bit.
 *
 * @remark Works only for n a power of two, and only for n up to 2^31.
 *
 * @param[in] n The power of two
 * @return the log base two of n
 */
int log2_pow2(uint32_t n) {
    const uint32_t b[] = {0xAAAAAAAA, 0xCCCCCCCC, 0xF0F0F0F0, 0xFF00FF00, 0xFFFF0000};
    register uint32_t r;
    r = (n & b[0]) != 0;
    r |= ((n & b[1]) != 0) << 1;
    r |= ((n & b[2]) != 0) << 2;
    r |= ((n & b[3]) != 0) << 3;
    r |= ((n & b[4]) != 0) << 4;
    return r;
}

/**
 * Reverse the bit order in a 32 bit integer.
 *
 * @remark This simply wraps the macro to enforce the type check.
 *
 * @param[in] a The integer to be reversed
 * @return An integer with the bits of @p a reversed
 */
uint32_t reverse_bits(uint32_t a) {
    return rev_4byte(a);
}

/**
 * Reverse the low-order bits in a 32 bit integer.
 *
 * The lowest log_base_two(@p n) bits of @p value are returned reversed. @p n must be a power of two.
 *
 * @param[in] n     To reverse `b` bits, set `n = 2 ^ b`
 * @param[in] value The bits to be reversed
 * @return The reversal of the lowest log_2(@p n) bits of the input @p value
 */
uint32_t reverse_bits_limited(uint32_t n, uint32_t value) {
    int unused_bit_len = 32 - log2_pow2(n);
    return reverse_bits(value) >> unused_bit_len;
}

/**
 * Reorder an array in reverse bit order of its indices.
 *
 * @remark Operates in-place on the array.
 * @remark Can handle arrays of any type: provide the element size in @p size.
 *
 * @param[in,out] values The array, which is re-ordered in-place
 * @param[in]     size   The size in bytes of an element of the array
 * @param[in]     n      The length of the array, must be a power of two less that 2^32
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 */
C_KZG_RET reverse_bit_order(void *values, size_t size, uint64_t n) {
    ASSERT(n >> 32 == 0, C_KZG_BADARGS);
    ASSERT(is_power_of_two(n), C_KZG_BADARGS);

    byte tmp[size];
    int unused_bit_len = 32 - log2_pow2(n);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t r = reverse_bits(i) >> unused_bit_len;
        if (r > i) {
            // Swap the two elements
            memcpy(tmp, values + (i * size), size);
            memcpy(values + (i * size), values + (r * size), size);
            memcpy(values + (r * size), tmp, size);
        }
    }

    return C_KZG_OK;
}

/**
 * The first part of the Toeplitz matrix multiplication algorithm: the Fourier
 * transform of the vector @p x extended.
 *
 * Used in #new_fk20_single_settings to calculate `x_ext_fft`.
 *
 * @param[out] out The FFT of the extension of @p x, size @p n * 2
 * @param[in]  x   The input vector, size @p n
 * @param[in]  n   The length of the input vector @p x
 * @param[in]  fs  The FFT settings previously initialised with #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET toeplitz_part_1(blst_p1 *out, const blst_p1 *x, uint64_t n, const FFTSettings *fs) {
    uint64_t n2 = n * 2;
    blst_p1 identity_g1, *x_ext;

    ASSERT(c_kzg_malloc((void **)&x_ext, n2 * sizeof *x_ext) == C_KZG_OK, C_KZG_MALLOC);

    blst_p1_from_affine(&identity_g1, &identity_g1_affine);
    for (uint64_t i = 0; i < n; i++) {
        x_ext[i] = x[i];
    }
    for (uint64_t i = n; i < n2; i++) {
        x_ext[i] = identity_g1;
    }

    ASSERT(fft_g1(out, x_ext, false, n2, fs) == C_KZG_OK, C_KZG_ERROR);

    free(x_ext);
    return C_KZG_OK;
}

/**
 * The second part of the Toeplitz matrix multiplication algorithm.
 *
 * @param[out] out Array of G1 group elements, length `n`
 * @param[in]  toeplitz_coeffs Toeplitz coefficients, a polynomial length `n`
 * @param[in]  fk  FK20 single settings previously initialised by #new_fk20_single_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET toeplitz_part_2(blst_p1 *out, const poly *toeplitz_coeffs, const FK20SingleSettings *fk) {
    blst_fr *toeplitz_coeffs_fft;

    ASSERT(toeplitz_coeffs->length == fk->x_ext_fft_len, C_KZG_BADARGS);
    ASSERT(c_kzg_malloc((void **)&toeplitz_coeffs_fft, toeplitz_coeffs->length * sizeof *toeplitz_coeffs_fft) ==
               C_KZG_OK,
           C_KZG_MALLOC);

    ASSERT(fft_fr(toeplitz_coeffs_fft, toeplitz_coeffs->coeffs, false, toeplitz_coeffs->length, fk->ks->fs) == C_KZG_OK,
           C_KZG_ERROR);

    for (uint64_t i = 0; i < toeplitz_coeffs->length; i++) {
        p1_mul(&out[i], &fk->x_ext_fft[i], &toeplitz_coeffs_fft[i]);
    }

    free(toeplitz_coeffs_fft);
    return C_KZG_OK;
}

/**
 * The third part of the Toeplitz matrix multiplication algorithm: transform back and zero the top half.
 *
 * @param[out] out Array of G1 group elements, length @p n2
 * @param[in]  h_ext_fft FFT of the extended `h` values, length @p n2
 * @param[in]  n2  Size of the arrays
 * @param[in]  fk  FK20 single settings previously initialised by #new_fk20_single_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_ERROR   An internal error occurred
 */
C_KZG_RET toeplitz_part_3(blst_p1 *out, const blst_p1 *h_ext_fft, uint64_t n2, const FK20SingleSettings *fk) {
    uint64_t n = n2 / 2;
    blst_p1 identity_g1;

    ASSERT(fft_g1(out, h_ext_fft, true, n2, fk->ks->fs) == C_KZG_OK, C_KZG_ERROR);

    // Zero the second half of h
    blst_p1_from_affine(&identity_g1, &identity_g1_affine);
    for (uint64_t i = n; i < n2; i++) {
        out[i] = identity_g1;
    }

    return C_KZG_OK;
}

/**
 * Reorder and extend polynomial coefficients for the toeplitz method.
 *
 * @remark Allocates space for the return polynomial that needs to be freed by calling #free_poly.
 *
 * @param[out] out The reordered polynomial, size `n * 2`
 * @param[in]  in  The input polynomial, size `n`
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET toeplitz_coeffs_step(poly *out, const poly *in) {
    uint64_t n = in->length, n2 = n * 2;

    ASSERT(init_poly(out, n2) == C_KZG_OK, C_KZG_MALLOC);

    out->coeffs[0] = in->coeffs[n - 1];
    for (uint64_t i = 1; i <= n + 1; i++) {
        out->coeffs[i] = fr_zero;
    }
    for (uint64_t i = n + 2; i < n2; i++) {
        out->coeffs[i] = in->coeffs[i - (n + 1)];
    }

    return C_KZG_OK;
}

/**
 * Optimised version of the FK20 algorithm for use in data availability checks.
 *
 * The upper half of the polynomial coefficients is always 0, so we do not need to extend to twice the size
 * for Toeplitz matrix multiplication.
 *
 * Simultaneously calculates all the KZG proofs for `x_i = w^i` (`0 <= i < 2n`), where `w` is a `(2 * n)`th root of
 * unity. The `2n` comes from the polynomial being extended with zeros to twice the original size.
 *
 * `out[i]` is the proof for `y[i]`, the evaluation of the polynomial at `fs.expanded_roots_of_unity[i]`.
 *
 * @param[out] out Array size `n * 2`
 * @param[in]  p   Polynomial, size `n`
 * @param[in]  fk  FK20 single settings previously initialised by #new_fk20_single_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET fk20_single_da_opt(blst_p1 *out, const poly *p, FK20SingleSettings *fk) {
    uint64_t n = p->length, n2 = n * 2;
    blst_p1 *h, *h_ext_fft;
    poly toeplitz_coeffs;
    C_KZG_RET ret;

    ASSERT(n2 <= fk->ks->fs->max_width, C_KZG_BADARGS);
    ASSERT(is_power_of_two(n), C_KZG_BADARGS);

    ASSERT(toeplitz_coeffs_step(&toeplitz_coeffs, p) == C_KZG_OK, C_KZG_MALLOC);

    ASSERT(c_kzg_malloc((void **)&h_ext_fft, toeplitz_coeffs.length * sizeof *h_ext_fft) == C_KZG_OK, C_KZG_MALLOC);
    ASSERT((ret = toeplitz_part_2(h_ext_fft, &toeplitz_coeffs, fk)) == C_KZG_OK,
           ret == C_KZG_MALLOC ? ret : C_KZG_ERROR);

    ASSERT(c_kzg_malloc((void **)&h, toeplitz_coeffs.length * sizeof *h) == C_KZG_OK, C_KZG_MALLOC);
    ASSERT(toeplitz_part_3(h, h_ext_fft, n2, fk) == C_KZG_OK, C_KZG_ERROR);

    ASSERT(fft_g1(out, h, false, n2, fk->ks->fs) == C_KZG_OK, C_KZG_ERROR);

    free(h);
    free(h_ext_fft);
    free_poly(&toeplitz_coeffs);
    return C_KZG_OK;
}

/**
 * Data availability using the FK20 single algorithm.
 *
 * Simultaneously calculates all the KZG proofs for `x_i = w^i` (`0 <= i < 2n`), where `w` is a `(2 * n)`th root of
 * unity. The `2n` comes from the polynomial being extended with zeros to twice the original size.
 *
 * `out[reverse_bits_limited(2 * n, i)]` is the proof for `y[i]`, the evaluation of the polynomial at
 * `fs.expanded_roots_of_unity[i]`.
 *
 * @param[out] out All the proofs, array length 2 * `n`
 * @param[in]  p   Polynomial, size `n`
 * @param[in]  fk  FK20 single settings previously initialised by #new_fk20_single_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 */
C_KZG_RET da_using_fk20_single(blst_p1 *out, const poly *p, FK20SingleSettings *fk) {
    uint64_t n = p->length, n2 = n * 2;

    ASSERT(n2 <= fk->ks->fs->max_width, C_KZG_BADARGS);
    ASSERT(is_power_of_two(n), C_KZG_BADARGS);

    ASSERT(fk20_single_da_opt(out, p, fk) == C_KZG_OK, C_KZG_ERROR);
    ASSERT(reverse_bit_order(out, sizeof out[0], n2) == C_KZG_OK, C_KZG_ERROR);

    return C_KZG_OK;
}

/**
 * Initialise settings for an FK20 single proof.
 *
 * #free_fk20_single_settings must be called to deallocate this structure.
 *
 * @param[out] fk The initialised settings
 * @param[in]  n2 The desired size of `x_ext_fft`, a power of two
 * @param[in]  ks KZGSettings that have already been initialised
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_fk20_single_settings(FK20SingleSettings *fk, uint64_t n2, const KZGSettings *ks) {
    int n = n2 / 2;
    blst_p1 *x;

    ASSERT(n2 <= ks->fs->max_width, C_KZG_BADARGS);
    ASSERT(is_power_of_two(n2), C_KZG_BADARGS);
    ASSERT(n2 >= 2, C_KZG_BADARGS);

    fk->ks = ks;
    fk->x_ext_fft_len = n2;

    ASSERT(c_kzg_malloc((void **)&x, n * sizeof *x) == C_KZG_OK, C_KZG_MALLOC);
    ASSERT(c_kzg_malloc((void **)&fk->x_ext_fft, fk->x_ext_fft_len * sizeof *fk->x_ext_fft) == C_KZG_OK, C_KZG_MALLOC);

    for (uint64_t i = 0; i < n - 1; i++) {
        x[i] = ks->secret_g1[n - 2 - i];
    }
    blst_p1_from_affine(&x[n - 1], &identity_g1_affine);

    ASSERT(toeplitz_part_1(fk->x_ext_fft, x, n, ks->fs) == C_KZG_OK, C_KZG_ERROR);

    free(x);
    return C_KZG_OK;
}

/**
 * Free the memory that was previously allocated by #new_fk20_single_settings.
 *
 * @param fk The settings to be freed
 */
void free_fk20_single_settings(FK20SingleSettings *fk) {
    free(fk->x_ext_fft);
    fk->x_ext_fft_len = 0;
}
