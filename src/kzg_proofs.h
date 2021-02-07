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

#include "c_kzg.h"
#include "fft_fr.h"
#include "poly.h"

typedef struct {
    FFTSettings *fs;
    blst_p1 *secret_g1;
    blst_p1 *extended_secret_g1;
    blst_p2 *secret_g2;
    uint64_t length;
} KZGSettings;

C_KZG_RET new_kzg_settings(KZGSettings *ks, FFTSettings *fs, blst_p1 *secret_g1, blst_p2 *secret_g2, uint64_t length);
void commit_to_poly(blst_p1 *out, const KZGSettings *ks, const poly *p);
C_KZG_RET compute_proof_single(blst_p1 *out, const KZGSettings *ks, poly *p, const blst_fr *x0);
C_KZG_RET check_proof_single(bool *out, const KZGSettings *ks, const blst_p1 *commitment, const blst_p1 *proof, const blst_fr *x, blst_fr *y);
C_KZG_RET compute_proof_multi(blst_p1 *out, const KZGSettings *ks, poly *p, const blst_fr *x0, uint64_t n);
C_KZG_RET check_proof_multi(bool *out, const KZGSettings *ks, const blst_p1 *commitment, const blst_p1 *proof, const blst_fr *x, const blst_fr *ys, uint64_t n);
