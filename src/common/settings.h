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

#pragma once

#include "common/fr.h"
#include "common/g1.h"
#include "common/g2.h"

////////////////////////////////////////////////////////////////////////////////////////////////////
// Types
////////////////////////////////////////////////////////////////////////////////////////////////////

/** Stores the setup and parameters needed for computing KZG proofs. */
typedef struct {
    /**
     * Roots of unity for the subgroup of size `domain_size`.
     *
     * The array contains `domain_size + 1` elements, it starts and ends with Fr::one().
     */
    fr_t *roots_of_unity;
    /**
     * Roots of unity for the subgroup of size `domain_size` in bit-reversed order.
     *
     * This array is derived by applying a bit-reversal permutation to `roots_of_unity`
     * excluding the last element. Essentially:
     *   `brp_roots_of_unity = bit_reversal_permutation(roots_of_unity[:-1])`
     *
     * The array contains `domain_size` elements.
     */
    fr_t *brp_roots_of_unity;
    /**
     * Roots of unity for the subgroup of size `domain_size` in reversed order.
     *
     * It is the reversed version of `roots_of_unity`. Essentially:
     *    `reverse_roots_of_unity = reverse(roots_of_unity)`
     *
     * This array is primarily used in FFTs.
     * The array contains `domain_size + 1` elements, it starts and ends with Fr::one().
     */
    fr_t *reverse_roots_of_unity;
    /** G1 group elements from the trusted setup in monomial form. */
    g1_t *g1_values_monomial;
    /** G1 group elements from the trusted setup in Lagrange form and bit-reversed order. */
    g1_t *g1_values_lagrange_brp;
    /** G2 group elements from the trusted setup in monomial form. */
    g2_t *g2_values_monomial;
    /** Data used during FK20 proof generation. */
    g1_t **x_ext_fft_columns;
    /** The precomputed tables for fixed-base MSM. */
    blst_p1_affine **tables;
    /** The window size for the fixed-base MSM. */
    size_t wbits;
    /** The scratch size for the fixed-base MSM. */
    size_t scratch_size;
} KZGSettings;
