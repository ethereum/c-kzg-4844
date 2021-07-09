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
 * @file c_kzg.h
 *
 * Type definitions and function prototypes for all user-accessible parts of the library.
 */

#ifndef C_KZG_H
#define C_KZG_H

#include "bls12_381.h"

/**
 * The common return type for all routines in which something can go wrong.
 *
 * @warning In the case of @p C_KZG_OK or @p C_KZG_BADARGS, the caller can assume that all memory allocated by the
 * called routines has been deallocated. However, in the case of @p C_KZG_ERROR or @p C_KZG_MALLOC being returned, these
 * are unrecoverable and memory may have been leaked.
 *
 * @todo Check that memory is not leaked anywhere in the case of C_KZG_BADARGS.
 */
typedef enum {
    C_KZG_OK = 0,  /**< Success! */
    C_KZG_BADARGS, /**< The supplied data is invalid in some way */
    C_KZG_ERROR,   /**< Internal error - this should never occur and may indicate a bug in the library */
    C_KZG_MALLOC,  /**< Could not allocate memory */
} C_KZG_RET;

//
// fft_common.c
//

/**
 * Stores the setup and parameters needed for performing FFTs.
 *
 * Initialise with #new_fft_settings. Free after use with #free_fft_settings.
 */
typedef struct {
    uint64_t max_width;            /**< The maximum size of FFT these settings support, a power of 2. */
    fr_t root_of_unity;            /**< The root of unity used to generate the lists in the structure. */
    fr_t *expanded_roots_of_unity; /**< Ascending powers of the root of unity, size `width + 1`. */
    fr_t *reverse_roots_of_unity;  /**< Descending powers of the root of unity, size `width + 1`. */
} FFTSettings;

C_KZG_RET new_fft_settings(FFTSettings *s, unsigned int max_scale);
void free_fft_settings(FFTSettings *s);

//
// fft_fr.c
//

C_KZG_RET fft_fr(fr_t *out, const fr_t *in, bool inverse, uint64_t n, const FFTSettings *fs);

//
// fft_g1.c
//

C_KZG_RET fft_g1(g1_t *out, const g1_t *in, bool inverse, uint64_t n, const FFTSettings *fs);

//
// poly.c
//

/**
 * Defines a polynomial whose coefficients are members of the finite field F_r.
 *
 * Initialise the storage with #new_poly. After use, free the storage with #free_poly.
 */
typedef struct {
    fr_t *coeffs;    /**< `coeffs[i]` is the coefficient of the `x^i` term of the polynomial. */
    uint64_t length; /**< One more than the polynomial's degree */
} poly;

void eval_poly(fr_t *out, const poly *p, const fr_t *x);
C_KZG_RET poly_inverse(poly *out, poly *b);
C_KZG_RET poly_mul(poly *out, const poly *a, const poly *b);
C_KZG_RET poly_mul_(poly *out, const poly *a, const poly *b, FFTSettings *fs);
C_KZG_RET new_poly_div(poly *out, const poly *dividend, const poly *divisor);
C_KZG_RET new_poly(poly *out, uint64_t length);
C_KZG_RET new_poly_with_coeffs(poly *out, const fr_t *coeffs, uint64_t length);
void free_poly(poly *p);

//
// kzg_proofs.c
//

/**
 * Stores the setup and parameters needed for computing KZG proofs.
 *
 * Initialise with #new_kzg_settings. Free after use with #free_kzg_settings.
 */
typedef struct {
    const FFTSettings *fs; /**< The corresponding settings for performing FFTs */
    g1_t *secret_g1;       /**< G1 group elements from the trusted setup */
    g2_t *secret_g2;       /**< G2 group elements from the trusted setup */
    uint64_t length;       /**< The number of elements in secret_g1 and secret_g2 */
} KZGSettings;

C_KZG_RET commit_to_poly(g1_t *out, const poly *p, const KZGSettings *ks);
C_KZG_RET compute_proof_single(g1_t *out, const poly *p, const fr_t *x0, const KZGSettings *ks);
C_KZG_RET check_proof_single(bool *out, const g1_t *commitment, const g1_t *proof, const fr_t *x, fr_t *y,
                             const KZGSettings *ks);
C_KZG_RET compute_proof_multi(g1_t *out, const poly *p, const fr_t *x0, uint64_t n, const KZGSettings *ks);
C_KZG_RET check_proof_multi(bool *out, const g1_t *commitment, const g1_t *proof, const fr_t *x, const fr_t *ys,
                            uint64_t n, const KZGSettings *ks);
C_KZG_RET new_kzg_settings(KZGSettings *ks, const g1_t *secret_g1, const g2_t *secret_g2, uint64_t length,
                           const FFTSettings *fs);
void free_kzg_settings(KZGSettings *ks);

//
// fk20_proofs.c
//

/**
 * Stores the setup and parameters needed for computing FK20 single proofs.
 *
 * Initialise with #new_fk20_single_settings. Free after use with #free_fk20_single_settings.
 */
typedef struct {
    const KZGSettings *ks;  /**< The corresponding settings for performing KZG proofs */
    g1_t *x_ext_fft;        /**< The output of the first part of the Toeplitz process */
    uint64_t x_ext_fft_len; /**< The length of the `x_ext_fft_len` array (TODO - do we need this?)*/
} FK20SingleSettings;

/**
 * Stores the setup and parameters needed for computing FK20 multi proofs.
 */
typedef struct {
    const KZGSettings *ks;  /**< The corresponding settings for performing KZG proofs */
    uint64_t chunk_len;     /**< TODO */
    g1_t **x_ext_fft_files; /**< TODO */
    uint64_t length;        /**< TODO */
} FK20MultiSettings;

C_KZG_RET da_using_fk20_single(g1_t *out, const poly *p, const FK20SingleSettings *fk);
C_KZG_RET da_using_fk20_multi(g1_t *out, const poly *p, const FK20MultiSettings *fk);
C_KZG_RET new_fk20_single_settings(FK20SingleSettings *fk, uint64_t n2, const KZGSettings *ks);
C_KZG_RET new_fk20_multi_settings(FK20MultiSettings *fk, uint64_t n2, uint64_t chunk_len, const KZGSettings *ks);
void free_fk20_single_settings(FK20SingleSettings *fk);
void free_fk20_multi_settings(FK20MultiSettings *fk);

//
// recover.c
//

C_KZG_RET recover_poly_from_samples(fr_t *reconstructed_data, fr_t *samples, uint64_t len_samples, FFTSettings *fs);

//
// zero_poly.c
//

C_KZG_RET zero_polynomial_via_multiplication(fr_t *zero_eval, poly *zero_poly, uint64_t width,
                                             const uint64_t *missing_indices, uint64_t len_missing,
                                             const FFTSettings *fs);

//
// das_extension.c
//

C_KZG_RET das_fft_extension(fr_t *vals, uint64_t n, const FFTSettings *fs);

#endif // C_KZG_H
