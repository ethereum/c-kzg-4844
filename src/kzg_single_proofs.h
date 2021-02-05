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
#include "kzg_common.h"
#include "poly.h"

void commit_to_poly(blst_p1 *out, const KZGSettings *ks, const poly *p);
C_KZG_RET compute_proof_single(blst_p1 *out, const KZGSettings *ks, poly *p, const uint64_t x0);
bool check_proof_single(const KZGSettings *ks, const blst_p1 *commitment, const blst_p1 *proof, const blst_fr *x, blst_fr *y);
