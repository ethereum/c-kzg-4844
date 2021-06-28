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
long run_bench(int scale_0, int scale_1, int max_seconds) {
    timespec_t t0, t1;
    unsigned long total_time = 0, nits = 0;

    uint64_t width_0 = (uint64_t)1 << scale_0;
    // uint64_t width_1 = (uint64_t)1 << scale_1;
    uint64_t width_1 = width_0 - ((uint64_t)1 << scale_1);

    int dividend_length = width_0;
    int divisor_length = width_1;

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

    new_poly(&q, dividend.length - divisor.length + 1);

    while (total_time < max_seconds * NANO) {
        clock_gettime(CLOCK_REALTIME, &t0);

#if 0
        assert(C_KZG_OK == poly_long_div(&q, &dividend, &divisor));
#else
        assert(C_KZG_OK == poly_fast_div(&q, &dividend, &divisor));
#endif
        clock_gettime(CLOCK_REALTIME, &t1);
        nits++;
        total_time += tdiff(t0, t1);
    }

    free_poly(&dividend);
    free_poly(&divisor);
    free_poly(&q);

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

    int scale_min = 5;
    int scale_max = 14;

#if 0
    printf("*** Benchmarking poly_long_div() %d second%s per test.\n", nsec, nsec == 1 ? "" : "s");
#else
    printf("*** Benchmarking poly_fast_div() %d second%s per test.\n", nsec, nsec == 1 ? "" : "s");
#endif
    printf(",");
    for (int i = /* scale_min */ 0; i <= scale_max; i++) {
        printf("%d,", i);
    }
    printf("\n");
    for (int scale_0 = scale_min; scale_0 <= scale_max; scale_0++) {
        printf("%d,", scale_0);
        for (int scale_1 = /* scale_min */ 0; scale_1 < scale_0; scale_1++) {
            printf("%lu,", run_bench(scale_0, scale_1, nsec));
        }
        printf("\n");
    }

    return EXIT_SUCCESS;
}
