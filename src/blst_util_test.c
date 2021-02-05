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
#include "blst_util.h"

// This is -1 (the second root of unity)
uint64_t m1[] = {0xffffffff00000000L, 0x53bda402fffe5bfeL, 0x3339d80809a1d805L, 0x73eda753299d7d48L};

void title(void) {;}

void fr_is_zero_works(void) {
    blst_fr zero;
    fr_from_uint64(&zero, 0);
    TEST_CHECK(fr_is_zero(&zero));
}

void fr_is_one_works(void) {
    TEST_CHECK(fr_is_one(&fr_one));
}

void fr_from_uint64_works(void) {
    blst_fr a;
    fr_from_uint64(&a, 1);
    TEST_CHECK(fr_is_one(&a));
}

void fr_equal_works(void) {
    // A couple of arbitrary roots of unity
    uint64_t aa[] = {0x0001000000000000L, 0xec03000276030000L, 0x8d51ccce760304d0L, 0x0000000000000000L};
    uint64_t bb[] = {0x8dd702cb688bc087L, 0xa032824078eaa4feL, 0xa733b23a98ca5b22L, 0x3f96405d25a31660L};
    blst_fr a, b;
    blst_fr_from_uint64(&a, aa);
    blst_fr_from_uint64(&b, bb);
    TEST_CHECK(true == fr_equal(&a, &a));
    TEST_CHECK(false == fr_equal(&a, &b));
}

void fr_negate_works(void) {
    blst_fr minus1, res;
    blst_fr_from_uint64(&minus1, m1);
    fr_negate(&res, &minus1);
    TEST_CHECK(fr_is_one(&res));
}

void p1_mul_works(void) {
    blst_fr minus1;
    blst_p1 g1_gen, g1_gen_neg, res;

    // Multiply the generator by minus one (the second root of unity)
    blst_p1_from_affine(&g1_gen, &BLS12_381_G1);
    blst_fr_from_uint64(&minus1, m1);
    p1_mul(&res, &g1_gen, &minus1);

    // We should end up with negative the generator
    blst_p1_from_affine(&g1_gen_neg, &BLS12_381_NEG_G1);

    TEST_CHECK(blst_p1_is_equal(&res, &g1_gen_neg));
}

void p1_sub_works(void) {
    blst_p1 g1_gen, g1_gen_neg;
    blst_p1 tmp, res;

    blst_p1_from_affine(&g1_gen, &BLS12_381_G1);
    blst_p1_from_affine(&g1_gen_neg, &BLS12_381_NEG_G1);

    // 2 * g1_gen = g1_gen - g1_gen_neg
    blst_p1_double(&tmp, &g1_gen);
    p1_sub(&res, &g1_gen, &g1_gen_neg);

    TEST_CHECK(blst_p1_is_equal(&tmp, &res));
}

void p2_mul_works(void) {
    blst_fr minus1;
    blst_p2 g2_gen, g2_gen_neg, res;

    // Multiply the generator by minus one (the second root of unity)
    blst_p2_from_affine(&g2_gen, &BLS12_381_G2);
    blst_fr_from_uint64(&minus1, m1);
    p2_mul(&res, &g2_gen, &minus1);

    // We should end up with negative the generator
    blst_p2_from_affine(&g2_gen_neg, &BLS12_381_NEG_G2);

    TEST_CHECK(blst_p2_is_equal(&res, &g2_gen_neg));
}

void p2_sub_works(void) {
    blst_p2 g2_gen, g2_gen_neg;
    blst_p2 tmp, res;

    blst_p2_from_affine(&g2_gen, &BLS12_381_G2);
    blst_p2_from_affine(&g2_gen_neg, &BLS12_381_NEG_G2);

    // 2 * g2_gen = g2_gen - g2_gen_neg
    blst_p2_double(&tmp, &g2_gen);
    p2_sub(&res, &g2_gen, &g2_gen_neg);

    TEST_CHECK(blst_p2_is_equal(&tmp, &res));
}

void identity_g1_is_infinity(void) {
    blst_p1 identity_g1;
    blst_p1_from_affine(&identity_g1, &identity_g1_affine);
    TEST_CHECK(blst_p1_is_inf(&identity_g1));
}

void g1_linear_combination(void) {
    int len = 255;
    blst_fr coeffs[len], tmp;
    blst_p1 p[len], res, exp, g1_gen;
    for (int i = 0; i < len; i++) {
        fr_from_uint64(coeffs + i, i + 1);
        blst_p1_from_affine(p + i, &BLS12_381_G1);
    }

    // Expected result
    fr_from_uint64(&tmp, len * (len + 1) / 2);
    blst_p1_from_affine(&g1_gen, &BLS12_381_G1);
    p1_mul(&exp, &g1_gen, &tmp);

    // Test result
    linear_combination_g1(&res, p, coeffs, len);
    TEST_CHECK(blst_p1_is_equal(&exp, &res));
}

void pairings_work(void) {
    // Verify that e([3]g1, [5]g2) = e([5]g1, [3]g2)
    blst_fr three, five;
    blst_p1 g1_3, g1_5;
    blst_p2 g2_3, g2_5;

    // Set up
    fr_from_uint64(&three, 3);
    fr_from_uint64(&five, 5);
    p1_mul(&g1_3, blst_p1_generator(), &three);
    p1_mul(&g1_5, blst_p1_generator(), &five);
    p2_mul(&g2_3, blst_p2_generator(), &three);
    p2_mul(&g2_5, blst_p2_generator(), &five);

    // Verify the pairing
    TEST_CHECK(true == pairings_verify(&g1_3, &g2_5, &g1_5, &g2_3));
    TEST_CHECK(false == pairings_verify(&g1_3, &g2_3, &g1_5, &g2_5));
}

TEST_LIST =
    {
     {"BLST_UTIL_TEST", title},
     {"fr_is_zero_works", fr_is_zero_works },
     {"fr_is_one_works", fr_is_one_works },
     {"fr_from_uint64_works", fr_from_uint64_works},
     {"fr_equal_works", fr_equal_works},
     {"fr_negate_works", fr_negate_works},
     {"p1_mul_works", p1_mul_works},
     {"p1_sub_works", p1_sub_works},
     {"p2_mul_works", p2_mul_works},
     {"p2_sub_works", p2_sub_works},
     {"identity_g1_is_infinity", identity_g1_is_infinity},
     {"g1_linear_combination", g1_linear_combination},
     {"pairings_work", pairings_work},
     { NULL, NULL }     /* zero record marks the end of the list */
    };
