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
#include "poly.h"

void title(void) {;}

void poly_div_length(void) {
    poly a, b;
    uint64_t len;
    init_poly(&a, 17);
    init_poly(&b, 5);
    TEST_CHECK(C_KZG_OK == poly_quotient_length(&len, &a, &b));
    TEST_CHECK(13 == len);
}

void poly_div_length_bad(void) {
    poly a, b;
    uint64_t len;
    init_poly(&a, 5);
    init_poly(&b, 17);
    TEST_CHECK(C_KZG_BADARGS == poly_quotient_length(&len, &a, &b));
}

void poly_div_0(void) {
    blst_fr a[3], b[2], c[2], expected[2];
    poly dividend, divisor, actual;

    // Calculate (x^2 - 1) / (x + 1) = x - 1

    // Dividend
    fr_from_uint64(&a[0], 1);
    fr_negate(&a[0], &a[0]);
    fr_from_uint64(&a[1], 0);
    fr_from_uint64(&a[2], 1);
    dividend.length = 3;
    dividend.coeffs = a;

    // Divisor
    fr_from_uint64(&b[0], 1);
    fr_from_uint64(&b[1], 1);
    divisor.length = 2;
    divisor.coeffs = b;

    // Known result
    fr_from_uint64(&expected[0], 1);
    fr_negate(&expected[0], &expected[0]);
    fr_from_uint64(&expected[1], 1);

    actual.length = 2;
    actual.coeffs = c;

    TEST_CHECK(C_KZG_OK == poly_long_div(&actual, &dividend, &divisor));
    TEST_CHECK(fr_equal(&expected[0], &actual.coeffs[0]));
    TEST_CHECK(fr_equal(&expected[1], &actual.coeffs[1]));
}

void poly_div_1(void) {
    blst_fr a[4], b[2], c[3], expected[3];
    poly dividend, divisor, actual;

    // Calculate (12x^3 - 11x^2 + 9x + 18) / (4x + 3) = 3x^2 - 5x + 6

    // Dividend
    fr_from_uint64(&a[0], 18);
    fr_from_uint64(&a[1], 9);
    fr_from_uint64(&a[2], 11);
    fr_negate(&a[2], &a[2]);
    fr_from_uint64(&a[3], 12);
    dividend.length = 4;
    dividend.coeffs = a;

    // Divisor
    fr_from_uint64(&b[0], 3);
    fr_from_uint64(&b[1], 4);
    divisor.length = 2;
    divisor.coeffs = b;

    // Known result
    fr_from_uint64(&expected[0], 6);
    fr_from_uint64(&expected[1], 5);
    fr_negate(&expected[1], &expected[1]);
    fr_from_uint64(&expected[2], 3);

    actual.length = 3;
    actual.coeffs = c;

    TEST_CHECK(C_KZG_OK == poly_long_div(&actual, &dividend, &divisor));
    TEST_CHECK(fr_equal(&expected[0], &actual.coeffs[0]));
    TEST_CHECK(fr_equal(&expected[1], &actual.coeffs[1]));
    TEST_CHECK(fr_equal(&expected[2], &actual.coeffs[2]));
}

void poly_wrong_size(void) {
    poly dividend, divisor, result;
    TEST_CHECK(C_KZG_BADARGS == poly_long_div(&result, &dividend, &divisor));
}

void poly_eval_check(void) {
    uint64_t n = 10;
    blst_fr res, expected;
    poly p;
    init_poly(&p, n);
    for (uint64_t i = 0; i < n; i++) {
        fr_from_uint64(&p.coeffs[i], i + 1);
    }
    fr_from_uint64(&expected, n * (n + 1) / 2);

    eval_poly(&res, &p, &fr_one);

    TEST_CHECK(fr_equal(&expected, &res));
}

void poly_eval_0_check(void) {
    uint64_t n = 7, a = 597;
    blst_fr res, expected;
    poly p;
    init_poly(&p, n);
    for (uint64_t i = 0; i < n; i++) {
        fr_from_uint64(&p.coeffs[i], i + a);
    }
    fr_from_uint64(&expected, a);

    eval_poly(&res, &p, &fr_zero);

    TEST_CHECK(fr_equal(&expected, &res));
}

TEST_LIST =
    {
     {"POLY_TEST", title},
     {"poly_div_length", poly_div_length},
     {"poly_div_length_bad", poly_div_length_bad},
     {"poly_div_0", poly_div_0},
     {"poly_div_1", poly_div_1},
     {"poly_wrong_size", poly_wrong_size},
     {"poly_eval_check", poly_eval_check},
     {"poly_eval_0_check", poly_eval_0_check},
     { NULL, NULL }     /* zero record marks the end of the list */
    };
