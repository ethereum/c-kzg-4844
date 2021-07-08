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

/** @file kzg_proofs.h */

#ifndef KZG_PROOFS_H
#define KZG_PROOFS_H

#include "fft_fr.h"
#include "poly.h"

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

#endif
