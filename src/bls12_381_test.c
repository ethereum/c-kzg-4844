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
#include "test_util.h"

// This is -1 (the second root of unity)
uint64_t m1[] = {0xffffffff00000000L, 0x53bda402fffe5bfeL, 0x3339d80809a1d805L, 0x73eda753299d7d48L};

void log_2_byte_works(void) {
    // TEST_CHECK(0 == log_2_byte(0x00));
    TEST_CHECK(0 == log_2_byte(0x01));
    TEST_CHECK(7 == log_2_byte(0x80));
    TEST_CHECK(7 == log_2_byte(0xff));
    TEST_CHECK(4 == log_2_byte(0x10));
}

void fr_is_zero_works(void) {
    fr_t zero;
    fr_from_uint64(&zero, 0);
    TEST_CHECK(fr_is_zero(&zero));
}

void fr_is_one_works(void) {
    TEST_CHECK(fr_is_one(&fr_one));
}

void fr_is_null_works(void) {
    TEST_CHECK(fr_is_null(&fr_null));
    TEST_CHECK(!fr_is_null(&fr_zero));
    TEST_CHECK(!fr_is_null(&fr_one));
}

void fr_from_uint64_works(void) {
    fr_t a;
    fr_from_uint64(&a, 1);
    TEST_CHECK(fr_is_one(&a));
}

void fr_equal_works(void) {
    // A couple of arbitrary roots of unity
    uint64_t aa[] = {0x0001000000000000L, 0xec03000276030000L, 0x8d51ccce760304d0L, 0x0000000000000000L};
    uint64_t bb[] = {0x8dd702cb688bc087L, 0xa032824078eaa4feL, 0xa733b23a98ca5b22L, 0x3f96405d25a31660L};
    fr_t a, b;
    fr_from_uint64s(&a, aa);
    fr_from_uint64s(&b, bb);
    TEST_CHECK(true == fr_equal(&a, &a));
    TEST_CHECK(false == fr_equal(&a, &b));
}

void fr_negate_works(void) {
    fr_t minus1, res;
    fr_from_uint64s(&minus1, m1);
    fr_negate(&res, &minus1);
    TEST_CHECK(fr_is_one(&res));
}

void fr_pow_works(void) {
    // a^pow
    uint64_t pow = 123456;
    fr_t a, expected, actual;
    fr_from_uint64(&a, 197);

    // Do it the slow way
    expected = fr_one;
    for (uint64_t i = 0; i < pow; i++) {
        fr_mul(&expected, &expected, &a);
    }

    // Do it the quick way
    fr_pow(&actual, &a, pow);

    TEST_CHECK(fr_equal(&expected, &actual));
}

void fr_div_works(void) {
    fr_t a, b, tmp, actual;

    fr_from_uint64(&a, 197);
    fr_from_uint64(&b, 123456);

    fr_div(&tmp, &a, &b);
    fr_mul(&actual, &tmp, &b);

    TEST_CHECK(fr_equal(&a, &actual));
}

// This is strictly undefined, but conventionally 0 is returned
void fr_div_by_zero(void) {
    fr_t a, b, tmp;

    fr_from_uint64(&a, 197);
    fr_from_uint64(&b, 0);

    fr_div(&tmp, &a, &b);

    TEST_CHECK(fr_is_zero(&tmp));
}

void p1_mul_works(void) {
    fr_t minus1;
    g1_t res;

    // Multiply the generator by minus one (the second root of unity)
    fr_from_uint64s(&minus1, m1);
    g1_mul(&res, &g1_generator, &minus1);

    // We should end up with negative the generator
    TEST_CHECK(g1_equal(&res, &g1_negative_generator));
}

void p1_sub_works(void) {
    g1_t tmp, res;

    // 2 * g1_gen = g1_gen - g1_gen_neg
    g1_dbl(&tmp, &g1_generator);
    g1_sub(&res, &g1_generator, &g1_negative_generator);

    TEST_CHECK(g1_equal(&tmp, &res));
}

void p2_mul_works(void) {
    fr_t minus1;
    g2_t res;

    // Multiply the generator by minus one (the second root of unity)
    fr_from_uint64s(&minus1, m1);
    g2_mul(&res, &g2_generator, &minus1);

    TEST_CHECK(g2_equal(&res, &g2_negative_generator));
}

void p2_sub_works(void) {
    g2_t tmp, res;

    // 2 * g2_gen = g2_gen - g2_gen_neg
    g2_dbl(&tmp, &g2_generator);
    g2_sub(&res, &g2_generator, &g2_negative_generator);

    TEST_CHECK(g2_equal(&tmp, &res));
}

void g1_identity_is_infinity(void) {
    TEST_CHECK(g1_is_inf(&g1_identity));
}

void g1_identity_is_identity(void) {
    g1_t actual;
    g1_add_or_dbl(&actual, &g1_generator, &g1_identity);
    TEST_CHECK(g1_equal(&g1_generator, &actual));
}

void g1_make_linear_combination(void) {
    int len = 255;
    fr_t coeffs[len], tmp;
    g1_t p[len], res, exp;
    for (int i = 0; i < len; i++) {
        fr_from_uint64(coeffs + i, i + 1);
        p[i] = g1_generator;
    }

    // Expected result
    fr_from_uint64(&tmp, len * (len + 1) / 2);
    g1_mul(&exp, &g1_generator, &tmp);

    // Test result
    g1_linear_combination(&res, p, coeffs, len);
    TEST_CHECK(g1_equal(&exp, &res));
}

void pairings_work(void) {
    // Verify that e([3]g1, [5]g2) = e([5]g1, [3]g2)
    fr_t three, five;
    g1_t g1_3, g1_5;
    g2_t g2_3, g2_5;

    // Set up
    fr_from_uint64(&three, 3);
    fr_from_uint64(&five, 5);
    g1_mul(&g1_3, &g1_generator, &three);
    g1_mul(&g1_5, &g1_generator, &five);
    g2_mul(&g2_3, &g2_generator, &three);
    g2_mul(&g2_5, &g2_generator, &five);

    // Verify the pairing
    TEST_CHECK(true == pairings_verify(&g1_3, &g2_5, &g1_5, &g2_3));
    TEST_CHECK(false == pairings_verify(&g1_3, &g2_3, &g1_5, &g2_5));
}

TEST_LIST = {
    {"BLS12_384_TEST", title},
    {"log_2_byte_works", log_2_byte_works},
    {"fr_is_zero_works", fr_is_zero_works},
    {"fr_is_one_works", fr_is_one_works},
    {"fr_is_null_works", fr_is_null_works},
    {"fr_from_uint64_works", fr_from_uint64_works},
    {"fr_equal_works", fr_equal_works},
    {"fr_negate_works", fr_negate_works},
    {"fr_pow_works", fr_pow_works},
    {"fr_div_works", fr_div_works},
    {"fr_div_by_zero", fr_div_by_zero},
    {"p1_mul_works", p1_mul_works},
    {"p1_sub_works", p1_sub_works},
    {"p2_mul_works", p2_mul_works},
    {"p2_sub_works", p2_sub_works},
    {"g1_identity_is_infinity", g1_identity_is_infinity},
    {"g1_identity_is_identity", g1_identity_is_identity},
    {"g1_make_linear_combination", g1_make_linear_combination},
    {"pairings_work", pairings_work},
    {NULL, NULL} /* zero record marks the end of the list */
};
