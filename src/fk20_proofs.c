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

/** @file fk20_proofs.c */

// FK20 refers to this technique: https://github.com/khovratovich/Kate/blob/master/Kate_amortized.pdf

#include <stdlib.h> // free()
#include <string.h> // memcpy()
#include "fk20_proofs.h"
#include "fft_g1.h"
#include "c_kzg_util.h"

// Log base 2 - only works for n a power of two
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

// This simply wraps the macro to enforce the type check
uint32_t reverse_bits(uint32_t a) {
    return rev_4byte(a);
}

uint32_t reverse_bits_limited(uint32_t length, uint32_t value) {
    int unused_bit_len = 32 - log2_pow2(length);
    return reverse_bits(value) >> unused_bit_len;
}

// In-place re-ordering of an array by the bit-reversal of the indices
// Can handle arrays of any type: provide the element size in `size`
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

// Performs the first part of the Toeplitz matrix multiplication algorithm, which is a Fourier
// transform of the vector x extended
C_KZG_RET toeplitz_part_1(blst_p1 *out, const blst_p1 *x, uint64_t n, KZGSettings *ks) {
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

    ASSERT(fft_g1(out, x_ext, false, n2, ks->fs) == C_KZG_OK, C_KZG_ERROR);

    free(x_ext);
    return C_KZG_OK;
}

// Performs the second part of the Toeplitz matrix multiplication algorithm
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

// Part 3: transform back and zero the top half
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

void toeplitz_coeffs_step(poly *out, const poly *in) {
    uint64_t n = in->length, n2 = n * 2;

    out->coeffs[0] = in->coeffs[n - 1];
    for (uint64_t i = 1; i <= n + 1; i++) {
        out->coeffs[i] = fr_zero;
    }
    for (uint64_t i = n + 2; i < n2; i++) {
        out->coeffs[i] = in->coeffs[i - (n + 1)];
    }
}

// Special version of the FK20 for the situation of data availability checks:
// The upper half of the polynomial coefficients is always 0, so we do not need to extend to twice the size
// for Toeplitz matrix multiplication
C_KZG_RET fk20_single_da_opt(blst_p1 *out, const poly *p, FK20SingleSettings *fk) {
    uint64_t n = p->length, n2 = n * 2;
    blst_p1 *h, *h_ext_fft;
    poly toeplitz_coeffs;
    C_KZG_RET ret;

    ASSERT(n2 <= fk->ks->fs->max_width, C_KZG_BADARGS);
    ASSERT(is_power_of_two(n), C_KZG_BADARGS);

    ASSERT(init_poly(&toeplitz_coeffs, n2) == C_KZG_OK, C_KZG_MALLOC);
    toeplitz_coeffs_step(&toeplitz_coeffs, p);

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
 * free_fk20_single_settings must be called to deallocate this structure.
 *
 * @param fk[out] The initialised settings
 * @param n2[in] The size
 * @param ks[in] KZGSettings that have already been initialised
 *
 * @return C_KZG_RET
 */
C_KZG_RET new_fk20_single_settings(FK20SingleSettings *fk, uint64_t n2, KZGSettings *ks) {
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

    ASSERT(toeplitz_part_1(fk->x_ext_fft, x, n, ks) == C_KZG_OK, C_KZG_ERROR);

    free(x);
    return C_KZG_OK;
}

void free_fk20_single_settings(FK20SingleSettings *fk) {
    free(fk->x_ext_fft);
}