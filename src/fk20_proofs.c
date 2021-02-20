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
 *
 * @todo Split this out into smaller files.
 */

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
    CHECK(n >> 32 == 0);
    CHECK(is_power_of_two(n));

    // Pointer arithmetic on `void *` is naughty, so cast to something definite
    byte *v = values;
    byte tmp[size];
    int unused_bit_len = 32 - log2_pow2(n);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t r = reverse_bits(i) >> unused_bit_len;
        if (r > i) {
            // Swap the two elements
            memcpy(tmp, v + (i * size), size);
            memcpy(v + (i * size), v + (r * size), size);
            memcpy(v + (r * size), tmp, size);
        }
    }

    return C_KZG_OK;
}

/**
 * The first part of the Toeplitz matrix multiplication algorithm: the Fourier
 * transform of the vector @p x extended.
 *
 * @param[out] out The FFT of the extension of @p x, size @p n * 2
 * @param[in]  x   The input vector, size @p n
 * @param[in]  n   The length of the input vector @p x
 * @param[in]  fs  The FFT settings previously initialised with #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET toeplitz_part_1(g1_t *out, const g1_t *x, uint64_t n, const FFTSettings *fs) {
    uint64_t n2 = n * 2;
    g1_t *x_ext;

    TRY(new_p1(&x_ext, n2));
    for (uint64_t i = 0; i < n; i++) {
        x_ext[i] = x[i];
    }
    for (uint64_t i = n; i < n2; i++) {
        x_ext[i] = g1_identity;
    }

    TRY(fft_g1(out, x_ext, false, n2, fs));

    free(x_ext);
    return C_KZG_OK;
}

/**
 * The second part of the Toeplitz matrix multiplication algorithm.
 *
 * @param[out] out Array of G1 group elements, length `n`
 * @param[in]  toeplitz_coeffs Toeplitz coefficients, a polynomial length `n`
 * @param[in]  x_ext_fft The Fourier transform of the extended `x` vector, length `n`
 * @param[in]  fs  The FFT settings previously initialised with #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET toeplitz_part_2(g1_t *out, const poly *toeplitz_coeffs, const g1_t *x_ext_fft, const FFTSettings *fs) {
    fr_t *toeplitz_coeffs_fft;

    // CHECK(toeplitz_coeffs->length == fk->x_ext_fft_len); // TODO: how to implement?

    TRY(new_fr(&toeplitz_coeffs_fft, toeplitz_coeffs->length));
    TRY(fft_fr(toeplitz_coeffs_fft, toeplitz_coeffs->coeffs, false, toeplitz_coeffs->length, fs));

    for (uint64_t i = 0; i < toeplitz_coeffs->length; i++) {
        g1_mul(&out[i], &x_ext_fft[i], &toeplitz_coeffs_fft[i]);
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
 * @param[in]  fs  The FFT settings previously initialised with #new_fft_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_ERROR   An internal error occurred
 */
C_KZG_RET toeplitz_part_3(g1_t *out, const g1_t *h_ext_fft, uint64_t n2, const FFTSettings *fs) {
    uint64_t n = n2 / 2;

    TRY(fft_g1(out, h_ext_fft, true, n2, fs));

    // Zero the second half of h
    for (uint64_t i = n; i < n2; i++) {
        out[i] = g1_identity;
    }

    return C_KZG_OK;
}

/**
 * Reorder and extend polynomial coefficients for the toeplitz method, strided version.
 *
 * @remark The upper half of the input polynomial coefficients is treated as being zero.
 *
 * @param[out] out The reordered polynomial, size `n * 2 / stride`
 * @param[in]  in  The input polynomial, size `n`
 * @param[in]  offset The offset
 * @param[in]  stride The stride
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET toeplitz_coeffs_stride(poly *out, const poly *in, uint64_t offset, uint64_t stride) {
    uint64_t n = in->length, k, k2;

    CHECK(stride > 0);

    k = n / stride;
    k2 = k * 2;

    out->coeffs[0] = in->coeffs[n - 1 - offset];
    for (uint64_t i = 1; i <= k + 1; i++) {
        out->coeffs[i] = fr_zero;
    }
    for (uint64_t i = k + 2, j = 2 * stride - offset - 1; i < k2; i++, j += stride) {
        out->coeffs[i] = in->coeffs[j];
    }

    return C_KZG_OK;
}

/**
 * Reorder and extend polynomial coefficients for the toeplitz method.
 *
 * @remark The upper half of the input polynomial coefficients is treated as being zero.
 *
 * @param[out] out The reordered polynomial, size `n * 2`
 * @param[in]  in  The input polynomial, size `n`
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET toeplitz_coeffs_step(poly *out, const poly *in) {
    return toeplitz_coeffs_stride(out, in, 0, 1);
}

/**
 * Optimised version of the FK20 algorithm for use in data availability checks.
 *
 * Simultaneously calculates all the KZG proofs for `x_i = w^i` (`0 <= i < 2n`), where `w` is a `(2 * n)`th root of
 * unity. The `2n` comes from the polynomial being extended with zeros to twice the original size.
 *
 * `out[i]` is the proof for `y[i]`, the evaluation of the polynomial at `fs.expanded_roots_of_unity[i]`.
 *
 * @remark Only the lower half of the polynomial is supplied; the upper, zero, half is assumed. The
 * #toeplitz_coeffs_step routine does the right thing.
 *
 * @param[out] out Array size `n * 2`
 * @param[in]  p   Polynomial, size `n`
 * @param[in]  fk  FK20 single settings previously initialised by #new_fk20_single_settings
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET fk20_single_da_opt(g1_t *out, const poly *p, const FK20SingleSettings *fk) {
    uint64_t n = p->length, n2 = n * 2;
    g1_t *h, *h_ext_fft;
    poly toeplitz_coeffs;

    CHECK(n2 <= fk->ks->fs->max_width);
    CHECK(is_power_of_two(n));

    TRY(new_poly(&toeplitz_coeffs, 2 * p->length));
    TRY(toeplitz_coeffs_step(&toeplitz_coeffs, p));

    TRY(new_p1(&h_ext_fft, toeplitz_coeffs.length));
    TRY(toeplitz_part_2(h_ext_fft, &toeplitz_coeffs, fk->x_ext_fft, fk->ks->fs));

    TRY(new_p1(&h, n2));
    TRY(toeplitz_part_3(h, h_ext_fft, n2, fk->ks->fs));

    TRY(fft_g1(out, h, false, n2, fk->ks->fs));

    free_poly(&toeplitz_coeffs);
    free(h_ext_fft);
    free(h);
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
C_KZG_RET da_using_fk20_single(g1_t *out, const poly *p, const FK20SingleSettings *fk) {
    uint64_t n = p->length, n2 = n * 2;

    CHECK(n2 <= fk->ks->fs->max_width);
    CHECK(is_power_of_two(n));

    TRY(fk20_single_da_opt(out, p, fk));
    TRY(reverse_bit_order(out, sizeof out[0], n2));

    return C_KZG_OK;
}

/**
 * FK20 Method to compute all proofs - multi proof method
 *
 * Toeplitz multiplication as per http://www.netlib.org/utk/people/JackDongarra/etemplates/node384.html
 *
 * For a polynomial of size `n`, let `w` be a `n`th root of unity. Then this method will return
 * `k = n / l` KZG proofs for the points:
 *
 * ```
 * proof[0]: w^(0*l + 0), w^(0*l + 1), ... w^(0*l + l - 1)
 * proof[1]: w^(1*l + 0), w^(1*l + 1), ... w^(1*l + l - 1)
 * ...
 * proof[i]: w^(i*l + 0), w^(i*l + 1), ... w^(i*l + l - 1)
 * ```
 *
 * @param[out] out The proofs, array size @p p->length * 2
 * @param[in]  p   The polynomial
 * @param[in]  fk  FK20 multi settings previously initialised by #new_fk20_multi_settings
 */
C_KZG_RET fk20_compute_proof_multi(g1_t *out, const poly *p, const FK20MultiSettings *fk) {
    uint64_t n = p->length, n2 = n * 2;
    g1_t *h_ext_fft, *h_ext_fft_file, *h;
    poly toeplitz_coeffs;

    CHECK(fk->ks->fs->max_width >= n2);

    TRY(new_p1(&h_ext_fft, n2));
    for (uint64_t i = 0; i < n2; i++) {
        h_ext_fft[i] = g1_identity;
    }

    TRY(new_poly(&toeplitz_coeffs, 2 * p->length));
    TRY(new_p1(&h_ext_fft_file, toeplitz_coeffs.length));
    for (uint64_t i = 0; i < fk->chunk_len; i++) {
        TRY(toeplitz_coeffs_step(&toeplitz_coeffs, p));
        TRY(toeplitz_part_2(h_ext_fft_file, &toeplitz_coeffs, fk->x_ext_fft_files[i], fk->ks->fs));
        for (uint64_t j = 0; j < n2; j++) {
            g1_add_or_dbl(&h_ext_fft[j], &h_ext_fft[j], &h_ext_fft_file[j]);
        }
    }
    free_poly(&toeplitz_coeffs);
    free(h_ext_fft_file);

    TRY(new_p1(&h, n2));
    TRY(toeplitz_part_3(h, h_ext_fft, n2, fk->ks->fs));

    TRY(fft_g1(out, h, false, n2, fk->ks->fs));

    free(h_ext_fft);
    free(h);
    return C_KZG_OK;
}

/**
 * FK20 multi-proof method, optimized for data availability where the top half of polynomial
 * coefficients is zero.
 *
 * @remark Only the lower half of the polynomial is supplied; the upper, zero, half is assumed. The
 * #toeplitz_coeffs_stride routine does the right thing.
 *
 * @param[out] out The proofs, array size `2 * n / fk->chunk_length`
 * @param[in]  p   The polynomial, length `n`
 * @param[in]  fk  FK20 multi settings previously initialised by #new_fk20_multi_settings
 */
C_KZG_RET fk20_multi_da_opt(g1_t *out, const poly *p, const FK20MultiSettings *fk) {
    uint64_t n = p->length, n2 = n * 2, k, k2;
    g1_t *h_ext_fft, *h_ext_fft_file, *h;
    poly toeplitz_coeffs;

    CHECK(n2 <= fk->ks->fs->max_width);
    CHECK(is_power_of_two(n));

    n = n2 / 2;
    k = n / fk->chunk_len;
    k2 = k * 2;

    TRY(new_p1(&h_ext_fft, k2));
    for (uint64_t i = 0; i < k2; i++) {
        h_ext_fft[i] = g1_identity;
    }

    TRY(new_poly(&toeplitz_coeffs, n2 / fk->chunk_len));
    TRY(new_p1(&h_ext_fft_file, toeplitz_coeffs.length));
    for (uint64_t i = 0; i < fk->chunk_len; i++) {
        TRY(toeplitz_coeffs_stride(&toeplitz_coeffs, p, i, fk->chunk_len));
        TRY(toeplitz_part_2(h_ext_fft_file, &toeplitz_coeffs, fk->x_ext_fft_files[i], fk->ks->fs));
        for (uint64_t j = 0; j < k2; j++) {
            g1_add_or_dbl(&h_ext_fft[j], &h_ext_fft[j], &h_ext_fft_file[j]);
        }
    }
    free_poly(&toeplitz_coeffs);
    free(h_ext_fft_file);

    // Calculate `h`
    TRY(new_p1(&h, k2));
    TRY(toeplitz_part_3(h, h_ext_fft, k2, fk->ks->fs));

    // Overwrite the second half of `h` with zero
    for (uint64_t i = k; i < k2; i++) {
        h[i] = g1_identity;
    }

    TRY(fft_g1(out, h, false, k2, fk->ks->fs));

    free(h_ext_fft);
    free(h);

    return C_KZG_OK;
}

/**
 * Computes all the KZG proofs for data availability checks.
 *
 * This involves sampling on the double domain and reordering according to reverse bit order.
 *
 */
C_KZG_RET da_using_fk20_multi(g1_t *out, const poly *p, const FK20MultiSettings *fk) {
    uint64_t n = p->length, n2 = n * 2;

    CHECK(n2 <= fk->ks->fs->max_width);
    CHECK(is_power_of_two(n));

    TRY(fk20_multi_da_opt(out, p, fk));
    TRY(reverse_bit_order(out, sizeof out[0], n2 / fk->chunk_len));

    return C_KZG_OK;
}

/**
 * Initialise settings for an FK20 single proof.
 *
 * @remark As with all functions prefixed `new_`, this allocates memory that needs to be reclaimed by calling
 * the corresponding `free_` function. In this case, #free_fk20_single_settings.
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
    g1_t *x;

    CHECK(n2 <= ks->fs->max_width);
    CHECK(is_power_of_two(n2));
    CHECK(n2 >= 2);

    fk->ks = ks;
    fk->x_ext_fft_len = n2;

    TRY(new_p1(&x, n));
    for (uint64_t i = 0; i < n - 1; i++) {
        x[i] = ks->secret_g1[n - 2 - i];
    }
    x[n - 1] = g1_identity;

    TRY(new_p1(&fk->x_ext_fft, 2 * n));
    TRY(toeplitz_part_1(fk->x_ext_fft, x, n, ks->fs));

    free(x);
    return C_KZG_OK;
}

/**
 * Initialise settings for an FK20 multi proof.
 *
 * @remark As with all functions prefixed `new_`, this allocates memory that needs to be reclaimed by calling the
 * corresponding `free_` function. In this case, #free_fk20_multi_settings.
 *
 * @param[out] fk The initialised settings
 * @param[in]  n2 The desired size of `x_ext_fft`, a power of two
 * @param[in]  chunk_len TODO
 * @param[in]  ks KZGSettings that have already been initialised
 * @retval C_CZK_OK      All is well
 * @retval C_CZK_BADARGS Invalid parameters were supplied
 * @retval C_CZK_ERROR   An internal error occurred
 * @retval C_CZK_MALLOC  Memory allocation failed
 */
C_KZG_RET new_fk20_multi_settings(FK20MultiSettings *fk, uint64_t n2, uint64_t chunk_len, const KZGSettings *ks) {
    uint64_t n, k;
    g1_t *x;

    CHECK(n2 <= ks->fs->max_width);
    CHECK(is_power_of_two(n2));
    CHECK(n2 >= 2);
    CHECK(chunk_len <= n2);
    CHECK(is_power_of_two(chunk_len));
    CHECK(chunk_len > 0);

    n = n2 / 2;
    k = n / chunk_len;

    fk->ks = ks;
    fk->chunk_len = chunk_len;

    // `x_ext_fft_files` is two dimensional. Allocate space for pointers to the rows.
    TRY(c_kzg_malloc((void **)&fk->x_ext_fft_files, chunk_len * sizeof *fk->x_ext_fft_files));

    TRY(new_p1(&x, k));
    for (uint64_t offset = 0; offset < chunk_len; offset++) {
        uint64_t start = n - chunk_len - 1 - offset;
        for (uint64_t i = 0, j = start; i + 1 < k; i++, j -= chunk_len) {
            x[i] = ks->secret_g1[j];
        }
        x[k - 1] = g1_identity;

        TRY(new_p1(&fk->x_ext_fft_files[offset], 2 * k));
        TRY(toeplitz_part_1(fk->x_ext_fft_files[offset], x, k, ks->fs));
    }

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

/**
 * Free the memory that was previously allocated by #new_fk20_multi_settings.
 *
 * @param fk The settings to be freed
 */
void free_fk20_multi_settings(FK20MultiSettings *fk) {
    for (uint64_t i = 0; i < fk->chunk_len; i++) {
        free((fk->x_ext_fft_files)[i]);
    }
    free(fk->x_ext_fft_files);
    fk->chunk_len = 0;
    fk->length = 0;
}
