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

#include "fft.h"

////////////////////////////////////////////////////////////////////////////////////////////////////
// FFT Functions for Field Elements
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Fast Fourier Transform.
 *
 * Recursively divide and conquer.
 *
 * @param[out]  out             The results (length `n`)
 * @param[in]   in              The input data (length `n * stride`)
 * @param[in]   stride          The input data stride
 * @param[in]   roots           Roots of unity (length `n * roots_stride`)
 * @param[in]   roots_stride    The stride interval among the roots of unity
 * @param[in]   n               Length of the FFT, must be a power of two
 */
static void fr_fft_fast(
    fr_t *out, const fr_t *in, size_t stride, const fr_t *roots, size_t roots_stride, size_t n
) {
    size_t half = n / 2;
    if (half > 0) {
        fr_t y_times_root;
        fr_fft_fast(out, in, stride * 2, roots, roots_stride * 2, half);
        fr_fft_fast(out + half, in + stride, stride * 2, roots, roots_stride * 2, half);
        for (size_t i = 0; i < half; i++) {
            blst_fr_mul(&y_times_root, &out[i + half], &roots[i * roots_stride]);
            blst_fr_sub(&out[i + half], &out[i], &y_times_root);
            blst_fr_add(&out[i], &out[i], &y_times_root);
        }
    } else {
        *out = *in;
    }
}

/**
 * The entry point for forward FFT over field elements.
 *
 * @param[out]  out The results (array of length n)
 * @param[in]   in  The input data (array of length n)
 * @param[in]   n   Length of the arrays
 * @param[in]   s   The trusted setup
 *
 * @remark The array lengths must be a power of two.
 * @remark Use fr_ifft() for inverse transformation.
 */
C_KZG_RET fr_fft(fr_t *out, const fr_t *in, size_t n, const KZGSettings *s) {
    /* Ensure the length is valid */
    if (n > FIELD_ELEMENTS_PER_EXT_BLOB || !is_power_of_two(n)) {
        return C_KZG_BADARGS;
    }

    size_t stride = FIELD_ELEMENTS_PER_EXT_BLOB / n;
    fr_fft_fast(out, in, 1, s->roots_of_unity, stride, n);

    return C_KZG_OK;
}

/**
 * The entry point for inverse FFT over field elements.
 *
 * @param[out]  out The results (array of length n)
 * @param[in]   in  The input data (array of length n)
 * @param[in]   n   Length of the arrays
 * @param[in]   s   The trusted setup
 *
 * @remark The array lengths must be a power of two.
 * @remark Use fr_fft() for forward transformation.
 */
C_KZG_RET fr_ifft(fr_t *out, const fr_t *in, size_t n, const KZGSettings *s) {
    /* Ensure the length is valid */
    if (n > FIELD_ELEMENTS_PER_EXT_BLOB || !is_power_of_two(n)) {
        return C_KZG_BADARGS;
    }

    size_t stride = FIELD_ELEMENTS_PER_EXT_BLOB / n;
    fr_fft_fast(out, in, 1, s->reverse_roots_of_unity, stride, n);

    fr_t inv_len;
    fr_from_uint64(&inv_len, n);
    blst_fr_inverse(&inv_len, &inv_len);
    for (size_t i = 0; i < n; i++) {
        blst_fr_mul(&out[i], &out[i], &inv_len);
    }
    return C_KZG_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// FFT Functions for G1 Points
////////////////////////////////////////////////////////////////////////////////////////////////////

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
static void g1_fft_fast(
    g1_t *out, const g1_t *in, uint64_t stride, const fr_t *roots, uint64_t roots_stride, uint64_t n
) {
    g1_t y_times_root;
    uint64_t half = n / 2;
    if (half > 0) { /* Tunable parameter */
        g1_fft_fast(out, in, stride * 2, roots, roots_stride * 2, half);
        g1_fft_fast(out + half, in + stride, stride * 2, roots, roots_stride * 2, half);
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
 * @remark Use g1_ifft() for inverse transformation.
 */
C_KZG_RET g1_fft(g1_t *out, const g1_t *in, size_t n, const KZGSettings *s) {
    /* Ensure the length is valid */
    if (n > FIELD_ELEMENTS_PER_EXT_BLOB || !is_power_of_two(n)) {
        return C_KZG_BADARGS;
    }

    uint64_t stride = FIELD_ELEMENTS_PER_EXT_BLOB / n;
    g1_fft_fast(out, in, 1, s->roots_of_unity, stride, n);

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
 * @remark Use g1_fft() for forward transformation.
 */
C_KZG_RET g1_ifft(g1_t *out, const g1_t *in, size_t n, const KZGSettings *s) {
    /* Ensure the length is valid */
    if (n > FIELD_ELEMENTS_PER_EXT_BLOB || !is_power_of_two(n)) {
        return C_KZG_BADARGS;
    }

    uint64_t stride = FIELD_ELEMENTS_PER_EXT_BLOB / n;
    g1_fft_fast(out, in, 1, s->reverse_roots_of_unity, stride, n);

    fr_t inv_len;
    fr_from_uint64(&inv_len, n);
    blst_fr_eucl_inverse(&inv_len, &inv_len);
    for (uint64_t i = 0; i < n; i++) {
        g1_mul(&out[i], &out[i], &inv_len);
    }

    return C_KZG_OK;
}