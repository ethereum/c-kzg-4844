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

void poly_div_length(void) {
    TEST_CHECK(3 == poly_long_div_length(4, 2));
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

    TEST_CHECK(poly_long_div(&actual, &dividend, &divisor) == C_KZG_SUCCESS);
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

    TEST_CHECK(poly_long_div(&actual, &dividend, &divisor) == C_KZG_SUCCESS);
    TEST_CHECK(fr_equal(&expected[0], &actual.coeffs[0]));
    TEST_CHECK(fr_equal(&expected[1], &actual.coeffs[1]));
    TEST_CHECK(fr_equal(&expected[2], &actual.coeffs[2]));
}

void poly_wrong_size(void) {
    poly dividend, divisor, result;
    TEST_CHECK(poly_long_div(&result, &dividend, &divisor) == C_KZG_BADARGS);
}

void eval_poly(void) {
    uint64_t n = 10;
    blst_fr res, expected;
    poly p;
    init_poly(&p, n);
    for (uint64_t i = 0; i < n; i++) {
        fr_from_uint64(&p.coeffs[i], i + 1);
    }
    fr_from_uint64(&expected, n * (n + 1) / 2);

    eval_poly_at(&res, &p, &one);

    TEST_CHECK(fr_equal(&expected, &res));
}

TEST_LIST =
    {
     {"poly_div_length", poly_div_length},
     {"poly_div_0", poly_div_0},
     {"poly_div_1", poly_div_1},
     {"poly_wrong_size", poly_wrong_size},
     {"eval_poly", eval_poly},
     { NULL, NULL }     /* zero record marks the end of the list */
    };
