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

#include "eip7594/fk20.h"
#include "common/alloc.h"
#include "common/lincomb.h"
#include "eip7594/cell.h"
#include "eip7594/fft.h"

#include <stdlib.h> /* For NULL */

/**
 * Reorder and extend polynomial coefficients for the toeplitz method, strided version.
 *
 * @param[out]  out     The reordered polynomial, size `n * 2 / stride`
 * @param[in]   in      The input polynomial, size `n`
 * @param[in]   n       The size of the input polynomial
 * @param[in]   offset  The offset
 * @param[in]   stride  The stride
 */
static C_KZG_RET toeplitz_coeffs_stride(
    fr_t *out, const fr_t *in, size_t n, size_t offset, size_t stride
) {
    size_t k, k2;

    if (stride == 0) return C_KZG_BADARGS;

    k = n / stride;
    k2 = k * 2;

    out[0] = in[n - 1 - offset];
    for (size_t i = 1; i <= k + 1 && i < k2; i++) {
        out[i] = FR_ZERO;
    }
    for (size_t i = k + 2, j = 2 * stride - offset - 1; i < k2; i++, j += stride) {
        out[i] = in[j];
    }

    return C_KZG_OK;
}

/**
 * Compute FK20 cell-proofs for a polynomial.
 *
 * @param[out]  out An array of CELLS_PER_EXT_BLOB proofs
 * @param[in]   p   The polynomial, an array of coefficients
 * @param[in]   n   The length of the polynomial
 * @param[in]   s   The trusted setup
 *
 * @remark The polynomial should have FIELD_ELEMENTS_PER_BLOB coefficients. Only the lower half of
 * the extended polynomial is supplied because the upper half is assumed to be zero.
 */
C_KZG_RET compute_fk20_proofs(g1_t *out, const fr_t *p, size_t n, const KZGSettings *s) {
    C_KZG_RET ret;
    size_t k, k2;

    blst_scalar *scalars = NULL;
    fr_t **coeffs = NULL;
    fr_t *toeplitz_coeffs = NULL;
    fr_t *toeplitz_coeffs_fft = NULL;
    g1_t *h = NULL;
    g1_t *h_ext_fft = NULL;
    limb_t *scratch = NULL;
    bool precompute = s->wbits != 0;

    /* Initialize length variables */
    k = n / FIELD_ELEMENTS_PER_CELL;
    k2 = k * 2;

    /* Do allocations */
    ret = new_fr_array(&toeplitz_coeffs, k2);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&toeplitz_coeffs_fft, k2);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&h_ext_fft, k2);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&h, k2);
    if (ret != C_KZG_OK) goto out;

    if (precompute) {
        /* Allocations for fixed-base MSM */
        ret = c_kzg_malloc((void **)&scratch, s->scratch_size);
        if (ret != C_KZG_OK) goto out;
        ret = c_kzg_calloc((void **)&scalars, FIELD_ELEMENTS_PER_CELL, sizeof(blst_scalar));
        if (ret != C_KZG_OK) goto out;
    }

    /* Allocate 2d array for coefficients by column */
    ret = c_kzg_calloc((void **)&coeffs, k2, sizeof(void *));
    if (ret != C_KZG_OK) goto out;
    for (size_t i = 0; i < k2; i++) {
        ret = new_fr_array(&coeffs[i], k);
        if (ret != C_KZG_OK) goto out;
    }

    /* Initialize values to zero */
    for (size_t i = 0; i < k2; i++) {
        h_ext_fft[i] = G1_IDENTITY;
    }

    /* Compute toeplitz coefficients and organize by column */
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_CELL; i++) {
        ret = toeplitz_coeffs_stride(toeplitz_coeffs, p, n, i, FIELD_ELEMENTS_PER_CELL);
        if (ret != C_KZG_OK) goto out;
        ret = fr_fft(toeplitz_coeffs_fft, toeplitz_coeffs, k2, s);
        if (ret != C_KZG_OK) goto out;
        for (size_t j = 0; j < k2; j++) {
            coeffs[j][i] = toeplitz_coeffs_fft[j];
        }
    }

    /* Compute h_ext_fft via MSM */
    for (size_t i = 0; i < k2; i++) {
        if (precompute) {
            /* Transform the field elements to 255-bit scalars */
            for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
                blst_scalar_from_fr(&scalars[j], &coeffs[i][j]);
            }
            const byte *scalars_arg[2] = {(byte *)scalars, NULL};

            /* A fixed-base MSM with precomputation */
            blst_p1s_mult_wbits(
                &h_ext_fft[i],
                s->tables[i],
                s->wbits,
                FIELD_ELEMENTS_PER_CELL,
                scalars_arg,
                BITS_PER_FIELD_ELEMENT,
                scratch
            );
        } else {
            /* A pretty fast MSM without precomputation */
            ret = g1_lincomb_fast(
                &h_ext_fft[i], s->x_ext_fft_columns[i], coeffs[i], FIELD_ELEMENTS_PER_CELL
            );
            if (ret != C_KZG_OK) goto out;
        }
    }

    ret = g1_ifft(h, h_ext_fft, k2, s);
    if (ret != C_KZG_OK) goto out;

    /* Zero the second half of h */
    for (size_t i = k; i < k2; i++) {
        h[i] = G1_IDENTITY;
    }

    ret = g1_fft(out, h, k2, s);
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(scalars);
    if (coeffs != NULL) {
        for (size_t i = 0; i < k2; i++) {
            c_kzg_free(coeffs[i]);
        }
        c_kzg_free(coeffs);
    }
    c_kzg_free(toeplitz_coeffs);
    c_kzg_free(toeplitz_coeffs_fft);
    c_kzg_free(h);
    c_kzg_free(h_ext_fft);
    c_kzg_free(scratch);
    return ret;
}
