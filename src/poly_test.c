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
#include "poly.h"

// If anyone has a nicer way to initialise these test data, I'd love to hear it.
typedef struct polydata {
    int length;
    int coeffs[];
} polydata;

// (x^2 - 1) / (x + 1) = x - 1
polydata test_0_0 = {3, {-1, 0, 1}};
polydata test_0_1 = {2, {1, 1}};
polydata test_0_2 = {2, {-1, 1}};

// (12x^3 - 11x^2 + 9x + 18) / (4x + 3) = 3x^2 - 5x + 6
polydata test_1_0 = {4, {18, 9, -11, 12}};
polydata test_1_1 = {2, {3, 4}};
polydata test_1_2 = {3, {6, -5, 3}};

// (x + 1) / (x^2 - 1) = nil
polydata test_2_0 = {2, {1, 1}};
polydata test_2_1 = {3, {-1, 0, 2}};
polydata test_2_2 = {0, {}};

// (10x^2 + 20x + 30) / 10 = x^2 + 2x + 3
polydata test_3_0 = {3, {30, 20, 10}};
polydata test_3_1 = {1, {10}};
polydata test_3_2 = {3, {3, 2, 1}};

// (x^2 + x) / (x + 1) = x
polydata test_4_0 = {3, {0, 1, 1}};
polydata test_4_1 = {2, {1, 1}};
polydata test_4_2 = {2, {0, 1}};

// (x^2 + x + 1) / 1 = x^2 + x + 1
polydata test_5_0 = {3, {1, 1, 1}};
polydata test_5_1 = {1, {1}};
polydata test_5_2 = {3, {1, 1, 1}};

// (x^2 + x + 1) / (0x + 1) = x^2 + x + 1
polydata test_6_0 = {3, {1, 1, 1}};
polydata test_6_1 = {2, {1, 0}}; // The highest coefficient is zero
polydata test_6_2 = {3, {1, 1, 1}};

polydata *test[][3] = {{&test_0_0, &test_0_1, &test_0_2}, {&test_1_0, &test_1_1, &test_1_2},
                       {&test_2_0, &test_2_1, &test_2_2}, {&test_3_0, &test_3_1, &test_3_2},
                       {&test_4_0, &test_4_1, &test_4_2}, {&test_5_0, &test_5_1, &test_5_2},
                       {&test_6_0, &test_6_1, &test_6_2}};

/* Internal utility function */
void new_test_poly(poly *p, polydata *data) {
    new_poly(p, data->length);
    for (int i = 0; i < p->length; i++) {
        int coeff = data->coeffs[i];
        if (coeff >= 0) {
            fr_from_uint64(&p->coeffs[i], coeff);
        } else {
            fr_from_uint64(&p->coeffs[i], -coeff);
            fr_negate(&p->coeffs[i], &p->coeffs[i]);
        }
    }
}

void poly_test_div(void) {
    poly dividend, divisor, expected, actual;
    int ntest = sizeof test / sizeof test[0];

    for (int i = 0; i < ntest; i++) {
        new_test_poly(&dividend, test[i][0]);
        new_test_poly(&divisor, test[i][1]);
        new_test_poly(&expected, test[i][2]);

        if (TEST_CHECK(C_KZG_OK == new_poly_div(&actual, &dividend, &divisor))) {
            if (TEST_CHECK(actual.length == expected.length)) {
                for (int j = 0; j < actual.length; j++) {
                    TEST_CHECK(fr_equal(&actual.coeffs[j], &expected.coeffs[j]));
                    TEST_MSG("Failed test %d with incorrect value", i);
                }
            } else {
                TEST_MSG("Failed test %d with incorrect length.", i);
            }
        } else {
            TEST_MSG("Failed test %d with bad return value.", i);
        }

        free_poly(&dividend);
        free_poly(&divisor);
        free_poly(&expected);
        free_poly(&actual);
    }
}

void poly_div_by_zero(void) {
    fr_t a[2];
    poly dividend, divisor, dummy;

    // Calculate (x + 1) / 0 = FAIL

    // Dividend
    fr_from_uint64(&a[0], 1);
    fr_from_uint64(&a[1], 1);
    dividend.length = 2;
    dividend.coeffs = a;

    // Divisor
    new_poly(&divisor, 0);

    TEST_CHECK(C_KZG_BADARGS == new_poly_div(&dummy, &dividend, &divisor));

    free_poly(&divisor);
    free_poly(&dummy);
}

void poly_eval_check(void) {
    uint64_t n = 10;
    fr_t actual, expected;
    poly p;
    new_poly(&p, n);
    for (uint64_t i = 0; i < n; i++) {
        fr_from_uint64(&p.coeffs[i], i + 1);
    }
    fr_from_uint64(&expected, n * (n + 1) / 2);

    eval_poly(&actual, &p, &fr_one);

    TEST_CHECK(fr_equal(&expected, &actual));

    free_poly(&p);
}

void poly_eval_0_check(void) {
    uint64_t n = 7, a = 597;
    fr_t actual, expected;
    poly p;
    new_poly(&p, n);
    for (uint64_t i = 0; i < n; i++) {
        fr_from_uint64(&p.coeffs[i], i + a);
    }
    fr_from_uint64(&expected, a);

    eval_poly(&actual, &p, &fr_zero);

    TEST_CHECK(fr_equal(&expected, &actual));

    free_poly(&p);
}

void poly_eval_nil_check(void) {
    uint64_t n = 0;
    fr_t actual;
    poly p;
    new_poly(&p, n);

    eval_poly(&actual, &p, &fr_one);

    TEST_CHECK(fr_equal(&fr_zero, &actual));

    free_poly(&p);
}

void poly_mul_direct_test(void) {

    // Calculate (3x^2 - 5x + 6) * (4x + 3) = 12x^3 - 11x^2 + 9x + 18
    static polydata multiplier_data = {3, {6, -5, 3}};
    static polydata multiplicand_data = {2, {3, 4}};
    static polydata expected_data = {4, {18, 9, -11, 12}};

    poly multiplicand, multiplier, expected, actual0, actual1;

    new_test_poly(&multiplicand, &multiplicand_data);
    new_test_poly(&multiplier, &multiplier_data);
    new_test_poly(&expected, &expected_data);

    new_poly(&actual0, 4);
    TEST_CHECK(C_KZG_OK == poly_mul_direct(&actual0, &multiplicand, &multiplier));
    TEST_CHECK(fr_equal(&expected.coeffs[0], &actual0.coeffs[0]));
    TEST_CHECK(fr_equal(&expected.coeffs[1], &actual0.coeffs[1]));
    TEST_CHECK(fr_equal(&expected.coeffs[2], &actual0.coeffs[2]));
    TEST_CHECK(fr_equal(&expected.coeffs[3], &actual0.coeffs[3]));

    // Check commutativity
    new_poly(&actual1, 4);
    TEST_CHECK(C_KZG_OK == poly_mul_direct(&actual1, &multiplier, &multiplicand));
    TEST_CHECK(fr_equal(&expected.coeffs[0], &actual1.coeffs[0]));
    TEST_CHECK(fr_equal(&expected.coeffs[1], &actual1.coeffs[1]));
    TEST_CHECK(fr_equal(&expected.coeffs[2], &actual1.coeffs[2]));
    TEST_CHECK(fr_equal(&expected.coeffs[3], &actual1.coeffs[3]));

    free_poly(&multiplicand);
    free_poly(&multiplier);
    free_poly(&expected);
    free_poly(&actual0);
    free_poly(&actual1);
}

void poly_mul_fft_test(void) {

    // Calculate (3x^2 - 5x + 6) * (4x + 3) = 12x^3 - 11x^2 + 9x + 18
    static polydata multiplier_data = {3, {6, -5, 3}};
    static polydata multiplicand_data = {2, {3, 4}};
    static polydata expected_data = {4, {18, 9, -11, 12}};

    poly multiplicand, multiplier, expected, actual0, actual1;

    new_test_poly(&multiplicand, &multiplicand_data);
    new_test_poly(&multiplier, &multiplier_data);
    new_test_poly(&expected, &expected_data);

    new_poly(&actual0, 4);
    TEST_CHECK(C_KZG_OK == poly_mul_fft(&actual0, &multiplicand, &multiplier, NULL));
    TEST_CHECK(fr_equal(&expected.coeffs[0], &actual0.coeffs[0]));
    TEST_CHECK(fr_equal(&expected.coeffs[1], &actual0.coeffs[1]));
    TEST_CHECK(fr_equal(&expected.coeffs[2], &actual0.coeffs[2]));
    TEST_CHECK(fr_equal(&expected.coeffs[3], &actual0.coeffs[3]));

    // Check commutativity
    new_poly(&actual1, 4);
    TEST_CHECK(C_KZG_OK == poly_mul_fft(&actual1, &multiplier, &multiplicand, NULL));
    TEST_CHECK(fr_equal(&expected.coeffs[0], &actual1.coeffs[0]));
    TEST_CHECK(fr_equal(&expected.coeffs[1], &actual1.coeffs[1]));
    TEST_CHECK(fr_equal(&expected.coeffs[2], &actual1.coeffs[2]));
    TEST_CHECK(fr_equal(&expected.coeffs[3], &actual1.coeffs[3]));

    free_poly(&multiplicand);
    free_poly(&multiplier);
    free_poly(&expected);
    free_poly(&actual0);
    free_poly(&actual1);
}

void poly_inverse_simple_0(void) {

    // 1 / (1 - x) = 1 + x + x^2 + ...

    poly p, q;
    int d = 16; // The number of terms to take

    new_poly(&p, 2);
    p.coeffs[0] = fr_one;
    p.coeffs[1] = fr_one;
    fr_negate(&p.coeffs[1], &p.coeffs[1]);

    new_poly(&q, d);
    TEST_CHECK(C_KZG_OK == poly_inverse(&q, &p));

    for (int i = 0; i < d; i++) {
        TEST_CHECK(fr_is_one(&q.coeffs[i]));
    }

    free_poly(&p);
    free_poly(&q);
}

void poly_inverse_simple_1(void) {

    // 1 / (1 + x) = 1 - x + x^2 - ...

    poly p, q;
    int d = 16; // The number of terms to take

    new_poly(&p, 2);
    p.coeffs[0] = fr_one;
    p.coeffs[1] = fr_one;

    new_poly(&q, d);
    TEST_CHECK(C_KZG_OK == poly_inverse(&q, &p));

    for (int i = 0; i < d; i++) {
        fr_t tmp = q.coeffs[i];
        if (i & 1) {
            fr_negate(&tmp, &tmp);
        }
        TEST_CHECK(fr_is_one(&tmp));
    }

    free_poly(&p);
    free_poly(&q);
}

void poly_mul_random(void) {

    // Compare the output of poly_mul_direct() and poly_mul_fft()

    poly multiplicand, multiplier;
    poly q0, q1;

    for (int k = 0; k < 256; k++) {

        int multiplicand_length = 1 + rand() % 1000;
        int multiplier_length = 1 + rand() % 1000;
        int out_length = 1 + rand() % 1000;

        new_poly(&multiplicand, multiplicand_length);
        new_poly(&multiplier, multiplier_length);

        for (int i = 0; i < multiplicand_length; i++) {
            multiplicand.coeffs[i] = rand_fr();
        }
        for (int i = 0; i < multiplier_length; i++) {
            multiplier.coeffs[i] = rand_fr();
        }

        // Ensure that the polynomials' orders corresponds to their lengths
        if (fr_is_zero(&multiplicand.coeffs[multiplicand.length - 1])) {
            multiplicand.coeffs[multiplicand.length - 1] = fr_one;
        }
        if (fr_is_zero(&multiplier.coeffs[multiplier.length - 1])) {
            multiplier.coeffs[multiplier.length - 1] = fr_one;
        }

        new_poly(&q0, out_length); // Truncate the result
        TEST_CHECK(C_KZG_OK == poly_mul_direct(&q0, &multiplicand, &multiplier));

        new_poly(&q1, out_length);
        TEST_CHECK(C_KZG_OK == poly_mul_fft(&q1, &multiplicand, &multiplier, NULL));

        TEST_CHECK(q1.length == q0.length);
        for (int i = 0; i < q0.length; i++) {
            if (!TEST_CHECK(fr_equal(&q0.coeffs[i], &q1.coeffs[i]))) {
                TEST_MSG("round = %d, i = %d, multiplicand_length = %lu, multiplier_length = %lu, out_length = %lu", k,
                         i, multiplicand.length, multiplier.length, q0.length);
            }
        }

        free_poly(&multiplicand);
        free_poly(&multiplier);
        free_poly(&q0);
        free_poly(&q1);
    }
}

void poly_div_random(void) {

    // Compare the output of poly_fast_div() and poly_long_div()

    poly dividend, divisor;
    poly q0, q1;

    for (int k = 0; k < 256; k++) {

        int dividend_length = 2 + rand() % 1000;
        int divisor_length = 1 + rand() % dividend_length;

        new_poly(&dividend, dividend_length);
        new_poly(&divisor, divisor_length);

        for (int i = 0; i < dividend_length; i++) {
            dividend.coeffs[i] = rand_fr();
        }
        for (int i = 0; i < divisor_length; i++) {
            divisor.coeffs[i] = rand_fr();
        }

        // Ensure that the polynomials' orders corresponds to their lengths
        if (fr_is_zero(&dividend.coeffs[dividend.length - 1])) {
            dividend.coeffs[dividend.length - 1] = fr_one;
        }
        if (fr_is_zero(&divisor.coeffs[divisor.length - 1])) {
            divisor.coeffs[divisor.length - 1] = fr_one;
        }

        new_poly(&q0, dividend.length - divisor.length + 1);
        TEST_CHECK(C_KZG_OK == poly_long_div(&q0, &dividend, &divisor));

        new_poly(&q1, dividend.length - divisor.length + 1);
        TEST_CHECK(C_KZG_OK == poly_fast_div(&q1, &dividend, &divisor));

        TEST_CHECK(q1.length == q0.length);
        for (int i = 0; i < q0.length; i++) {
            if (!TEST_CHECK(fr_equal(&q0.coeffs[i], &q1.coeffs[i]))) {
                TEST_MSG("round = %d, dividend_length = %lu, divisor_length = %lu, i = %d", k, dividend.length,
                         divisor.length, i);
            }
        }

        free_poly(&dividend);
        free_poly(&divisor);
        free_poly(&q0);
        free_poly(&q1);
    }
}

TEST_LIST = {
    {"POLY_TEST", title},
    {"poly_test_div", poly_test_div},
#ifndef DEBUG
    {"poly_div_by_zero", poly_div_by_zero},
#endif
    {"poly_eval_check", poly_eval_check},
    {"poly_eval_0_check", poly_eval_0_check},
    {"poly_eval_nil_check", poly_eval_nil_check},
    {"poly_mul_direct_test", poly_mul_direct_test},
    {"poly_mul_fft_test", poly_mul_fft_test},
    {"poly_inverse_simple_0", poly_inverse_simple_0},
    {"poly_inverse_simple_1", poly_inverse_simple_1},
    {"poly_mul_random", poly_mul_random},
    {"poly_div_random", poly_div_random},
    {NULL, NULL} /* zero record marks the end of the list */
};
