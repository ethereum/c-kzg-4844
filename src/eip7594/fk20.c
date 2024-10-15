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
 * @param[out]  out     The reordered polynomial, length `CELLS_PER_EXT_BLOB`
 * @param[in]   in      The input polynomial, length `FIELD_ELEMENTS_PER_BLOB`
 * @param[in]   offset  The offset
 */
static void toeplitz_coeffs_stride(fr_t *out, const fr_t *in, size_t offset) {
    /* Calculate starting indices */
    size_t out_start = CELLS_PER_BLOB + 2;
    size_t in_start = CELLS_PER_EXT_BLOB - offset - 1;

    /* Set the first element */
    out[0] = in[FIELD_ELEMENTS_PER_BLOB - 1 - offset];

    /* Initialize these elements to zero */
    for (size_t i = 1; i < out_start; i++) {
        out[i] = FR_ZERO;
    }

    /* Copy elements with a fixed stride */
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB - out_start; i++) {
        out[out_start + i] = in[in_start + i * FIELD_ELEMENTS_PER_CELL];
    }
}

/**
 * Compute FK20 cell-proofs for a polynomial.
 *
 * @param[out]  out An array of CELLS_PER_EXT_BLOB proofs
 * @param[in]   p   The polynomial, an array of FIELD_ELEMENTS_PER_BLOB coefficients
 * @param[in]   s   The trusted setup
 *
 * @remark The polynomial should have FIELD_ELEMENTS_PER_BLOB coefficients. Only the lower half of
 * the extended polynomial is supplied because the upper half is assumed to be zero.
 */
C_KZG_RET compute_fk20_cell_proofs(g1_t *out, const fr_t *p, const KZGSettings *s) {
    C_KZG_RET ret;
    size_t circulant_domain_size;

    blst_scalar *scalars = NULL;
    fr_t **coeffs = NULL;
    fr_t *toeplitz_coeffs = NULL;
    fr_t *toeplitz_coeffs_fft = NULL;
    g1_t *h = NULL;
    g1_t *h_ext_fft = NULL;
    limb_t *scratch = NULL;
    bool precompute = s->wbits != 0;

    /*
     * Note: this constant 2 is not related to `LOG_EXPANSION_FACTOR`.
     * Instead, it is related to circulant matrices used in FK20, see
     * Section 2.2 and 3.2 in https://eprint.iacr.org/2023/033.pdf.
     */
    circulant_domain_size = CELLS_PER_BLOB * 2;

    /* Do allocations */
    ret = new_fr_array(&toeplitz_coeffs, circulant_domain_size);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&toeplitz_coeffs_fft, circulant_domain_size);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&h_ext_fft, circulant_domain_size);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&h, circulant_domain_size);
    if (ret != C_KZG_OK) goto out;

    if (precompute) {
        /* Allocations for fixed-base MSM */
        ret = c_kzg_malloc((void **)&scratch, s->scratch_size);
        if (ret != C_KZG_OK) goto out;
        ret = c_kzg_calloc((void **)&scalars, FIELD_ELEMENTS_PER_CELL, sizeof(blst_scalar));
        if (ret != C_KZG_OK) goto out;
    }

    /* Allocate 2d array for coefficients by column */
    ret = c_kzg_calloc((void **)&coeffs, circulant_domain_size, sizeof(void *));
    if (ret != C_KZG_OK) goto out;
    for (size_t i = 0; i < circulant_domain_size; i++) {
        ret = new_fr_array(&coeffs[i], CELLS_PER_BLOB);
        if (ret != C_KZG_OK) goto out;
    }

    /* Initialize values to zero */
    for (size_t i = 0; i < circulant_domain_size; i++) {
        h_ext_fft[i] = G1_IDENTITY;
    }

    /* Compute toeplitz coefficients and organize by column */
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_CELL; i++) {
        toeplitz_coeffs_stride(toeplitz_coeffs, p, i);
        ret = fr_fft(toeplitz_coeffs_fft, toeplitz_coeffs, circulant_domain_size, s);
        if (ret != C_KZG_OK) goto out;
        for (size_t j = 0; j < circulant_domain_size; j++) {
            coeffs[j][i] = toeplitz_coeffs_fft[j];
        }
    }

    /* Compute h_ext_fft via MSM */
    for (size_t i = 0; i < circulant_domain_size; i++) {
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

    ret = g1_ifft(h, h_ext_fft, circulant_domain_size, s);
    if (ret != C_KZG_OK) goto out;

    /* Zero the second half of h */
    for (size_t i = CELLS_PER_BLOB; i < circulant_domain_size; i++) {
        h[i] = G1_IDENTITY;
    }

    ret = g1_fft(out, h, circulant_domain_size, s);
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(scalars);
    if (coeffs != NULL) {
        for (size_t i = 0; i < circulant_domain_size; i++) {
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
