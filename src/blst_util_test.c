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

void fr_is_one_works(void) {
    TEST_CHECK(true == fr_is_one(&one));
}

void fr_from_uint64_works(void) {
    blst_fr a;
    fr_from_uint64(&a, 1);
    TEST_CHECK(true == fr_is_one(&a));
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

void p1_mul_works(void) {
    // This is -1 (the second root of unity)
    uint64_t m1[] = {0xffffffff00000000L, 0x53bda402fffe5bfeL, 0x3339d80809a1d805L, 0x73eda753299d7d48L};
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



TEST_LIST =
    {
     {"fr_is_one_works", fr_is_one_works },
     {"fr_from_uint64_works", fr_from_uint64_works},
     {"fr_equal_works", fr_equal_works},
     {"p1_mul_works", p1_mul_works},
     {"p1_sub_works", p1_sub_works},
     { NULL, NULL }     /* zero record marks the end of the list */
    };
