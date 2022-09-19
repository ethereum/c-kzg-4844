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
 * @file c_kzg_4844.h
 *
 * Minimal interface required for EIP-4844.
 */

#ifndef C_KZG_4844_H
#define C_KZG_4844_H

#include "c_kzg.h"
#include "control.h"

typedef fr_t BLSFieldElement;
typedef g1_t KZGCommitment;
typedef g1_t KZGProof;
typedef poly_l PolynomialEvalForm;

void load_trusted_setup(KZGSettings *out); // TODO: decide on input format and add appropriate arguments

void free_trusted_setup(KZGSettings *s);

void compute_powers(BLSFieldElement out[], const BLSFieldElement *x, uint64_t n);

void vector_lincomb(BLSFieldElement out[], const BLSFieldElement *vectors, const BLSFieldElement *scalars, uint64_t num_vectors, uint64_t vector_len);

void g1_lincomb(KZGCommitment *out, const KZGCommitment points[], const BLSFieldElement scalars[], uint64_t num_points);

void bytes_to_bls_field(BLSFieldElement *out, const scalar_t *bytes);

C_KZG_RET evaluate_polynomial_in_evaluation_form(BLSFieldElement *out, const PolynomialEvalForm *polynomial, const BLSFieldElement *z, const KZGSettings *s);

C_KZG_RET verify_kzg_proof(bool *out, const KZGCommitment *polynomial_kzg, const BLSFieldElement *z, const BLSFieldElement *y, const KZGProof *kzg_proof, const KZGSettings *s);

C_KZG_RET compute_kzg_proof(KZGProof *out, const PolynomialEvalForm *polynomial, const BLSFieldElement *z, const KZGSettings *s);

#endif // C_KZG_4844_H
