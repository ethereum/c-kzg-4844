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

#include "../inc/acutest.h"
#include "debug_util.h"
#include "kzg_single_proofs.h"

void generate_setup(blst_p1 *s1, blst_p2 *s2, const blst_scalar *secret, const uint64_t n) {
    blst_fr s_pow, s;
    blst_fr_from_scalar(&s, secret);
    s_pow = one;
    for (uint64_t i = 0; i < n; i++) {
        p1_mul(&s1[i], blst_p1_generator(), &s_pow);
        p2_mul(&s2[i], blst_p2_generator(), &s_pow);
        blst_fr_mul(&s_pow, &s_pow, &s);
    }
}

void title(void) {;}

void proof_single(void) {
    FFTSettings fs;
    KZGSettings ks;
    poly p;
    blst_p1 commitment, proof;
    blst_p1 *s1 = malloc(17 * sizeof(blst_p1));
    blst_p2 *s2 = malloc(17 * sizeof(blst_p2));
    blst_scalar secret =
        {
         0xa4, 0x73, 0x31, 0x95, 0x28, 0xc8, 0xb6, 0xea,
         0x4d, 0x08,0xcc, 0x53, 0x18, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        }; // Little-endian?
    uint64_t coeffs_u[16] = {1, 2, 3, 4, 7, 7, 7, 7, 13, 13, 13, 13, 13, 13, 13, 13};
    blst_fr x, value;

    poly_init(&p, 16);
    for (int i = 0; i < 16; i++) {
        fr_from_uint64(&p.coeffs[i], coeffs_u[i]);
    }

    generate_setup(s1, s2, &secret, 17);
    new_fft_settings(&fs, 4);
    new_kzg_settings(&ks, &fs, s1, s2, 17);

    commit_to_poly(&commitment, &ks, &p);
    compute_proof_single(&proof, &ks, &p, 17);

    fr_from_uint64(&x, 17);
    poly_eval(&value, &p, &x);

    TEST_CHECK(true == check_proof_single(&ks, &commitment, &proof, &x, &value));

    free(s1);
    free(s2);
}

TEST_LIST =
    {
     {"KZG_SINGLE_PRROFS_TEST", title},
     {"proof_single", proof_single},
     { NULL, NULL }     /* zero record marks the end of the list */
    };
