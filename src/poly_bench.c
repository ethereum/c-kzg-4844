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

#include <stdlib.h> // malloc(), free(), atoi()
#include <stdio.h>  // printf()
#include <assert.h> // assert()
#include <unistd.h> // EXIT_SUCCESS/FAILURE
#include "bench_util.h"
#include "test_util.h"
#include "poly.h"

// Run the benchmark for `max_seconds` and return the time per iteration in nanoseconds.
long run_bench(int scale, int max_seconds) {
    timespec_t t0, t1;
    unsigned long total_time = 0, nits = 0;

    uint64_t width = (uint64_t)1 << scale;

    int dividend_length = width;
    int divisor_length = width / 2; // What would be a relevant value of kzg multi-proofs?

    poly dividend, divisor, q;
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

    while (total_time < max_seconds * NANO) {
        clock_gettime(CLOCK_REALTIME, &t0);

        assert(C_KZG_OK == new_poly_div(&q, &dividend, &divisor));

        clock_gettime(CLOCK_REALTIME, &t1);
        nits++;
        total_time += tdiff(t0, t1);

        free_poly(&q);
    }

    free_poly(&dividend);
    free_poly(&divisor);

    return total_time / nits;
}

int main(int argc, char *argv[]) {
    int nsec = 0;

    switch (argc) {
    case 1:
        nsec = NSEC;
        break;
    case 2:
        nsec = atoi(argv[1]);
        break;
    default:
        break;
    };

    if (nsec == 0) {
        printf("Usage: %s [test time in seconds > 0]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("*** Benchmarking Polynomial Division, %d second%s per test.\n", nsec, nsec == 1 ? "" : "s");
    for (int scale = 6; scale <= 15; scale++) {
        printf("new_poly_div/scale_%d %lu ns/op\n", scale, run_bench(scale, nsec));
    }

    return EXIT_SUCCESS;
}
