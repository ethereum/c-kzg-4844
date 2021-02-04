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
#include "poly.h"

void poly_div_length() {
    TEST_CHECK(3 == poly_long_div_length(4, 2));
}

void poly_div_0() {
    // Calculate (x^2 - 1) / (x + 1) = x - 1
    blst_fr dividend[3];
    blst_fr divisor[2];
    blst_fr expected[2], actual[2];

    // Set up dividend
    fr_from_uint64(&dividend[0], 1);
    fr_negate(&dividend[0], &dividend[0]);
    fr_from_uint64(&dividend[1], 0);
    fr_from_uint64(&dividend[2], 1);

    // Set up divisor
    fr_from_uint64(&divisor[0], 1);
    fr_from_uint64(&divisor[1], 1);

    // Set up result
    fr_from_uint64(&expected[0], 1);
    fr_negate(&expected[0], &expected[0]);
    fr_from_uint64(&expected[1], 1);

    TEST_CHECK(poly_long_div(actual, 2, dividend, 3, divisor, 2) == C_KZG_SUCCESS);
    TEST_CHECK(fr_equal(expected + 0, actual + 0));
    TEST_CHECK(fr_equal(expected + 1, actual + 1));
}

void poly_div_1() {
    // Calculate (12x^3 - 11x^2 + 9x + 18) / (4x + 3) = 3x^2 - 5x + 6
    blst_fr dividend[4];
    blst_fr divisor[2];
    blst_fr expected[3], actual[3];

    // Set up dividend
    fr_from_uint64(&dividend[0], 18);
    fr_from_uint64(&dividend[1], 9);
    fr_from_uint64(&dividend[2], 11);
    fr_negate(&dividend[2], &dividend[2]);
    fr_from_uint64(&dividend[3], 12);

    // Set up divisor
    fr_from_uint64(&divisor[0], 3);
    fr_from_uint64(&divisor[1], 4);

    // Set up result
    fr_from_uint64(&expected[0], 6);
    fr_from_uint64(&expected[1], 5);
    fr_negate(&expected[1], &expected[1]);
    fr_from_uint64(&expected[2], 3);

    TEST_CHECK(poly_long_div(actual, 3, dividend, 4, divisor, 2) == C_KZG_SUCCESS);
    TEST_CHECK(fr_equal(expected + 0, actual + 0));
    TEST_CHECK(fr_equal(expected + 1, actual + 1));
    TEST_CHECK(fr_equal(expected + 2, actual + 2));
}

void poly_wrong_size(void) {
    blst_fr dividend[1], divisor[1], result[1];
    TEST_CHECK(poly_long_div(result, 5, dividend, 20, divisor, 7) == C_KZG_BADARGS);
}

TEST_LIST =
    {
     {"poly_div_length", poly_div_length},
     {"poly_div_0", poly_div_0},
     {"poly_div_1", poly_div_1},
     {"poly_wrong_size", poly_wrong_size},
     { NULL, NULL }     /* zero record marks the end of the list */
    };
