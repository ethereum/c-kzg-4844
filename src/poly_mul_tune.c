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
#include "c_kzg.h"

// Run the benchmark for `max_seconds` and return the time per iteration in nanoseconds.
long run_bench(int scale_0, int scale_1, int max_seconds) {
    timespec_t t0, t1;
    unsigned long total_time = 0, nits = 0;

    uint64_t width_0 = (uint64_t)1 << scale_0;
    uint64_t width_1 = (uint64_t)1 << scale_1;

    poly multiplicand, multiplier, r;
    new_poly(&multiplicand, width_0);
    new_poly(&multiplier, width_1);

    for (int i = 0; i < width_0; i++) {
        multiplicand.coeffs[i] = rand_fr();
    }
    for (int i = 0; i < width_1; i++) {
        multiplier.coeffs[i] = rand_fr();
    }

    // Ensure that the polynomials' orders corresponds to their lengths
    if (fr_is_zero(&multiplicand.coeffs[multiplicand.length - 1])) {
        multiplicand.coeffs[multiplicand.length - 1] = fr_one;
    }
    if (fr_is_zero(&multiplier.coeffs[multiplier.length - 1])) {
        multiplier.coeffs[multiplier.length - 1] = fr_one;
    }

    new_poly(&r, multiplicand.length + multiplier.length - 1);

    while (total_time < max_seconds * NANO) {
        clock_gettime(CLOCK_REALTIME, &t0);

#if 0
        assert(C_KZG_OK == poly_mul_fft(&r, &multiplicand, &multiplier, NULL));
#else
        assert(C_KZG_OK == poly_mul(&r, &multiplicand, &multiplier));
#endif

        clock_gettime(CLOCK_REALTIME, &t1);
        nits++;
        total_time += tdiff(t0, t1);
    }

    free_poly(&multiplicand);
    free_poly(&multiplier);
    free_poly(&r);

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
    int scale_max = 12;

#if 1
    printf("*** Benchmarking poly_mul_fft() %d second%s per test.\n", nsec, nsec == 1 ? "" : "s");
#else
    printf("*** Benchmarking poly_mul_direct() %d second%s per test.\n", nsec, nsec == 1 ? "" : "s");
#endif
    printf(",");
    for (int i = scale_min; i <= scale_max; i++) {
        printf("%d,", i);
    }
    printf("\n");
    for (int scale_0 = scale_min; scale_0 <= scale_max; scale_0++) {
        printf("%d,", scale_0);
        for (int scale_1 = scale_min; scale_1 <= scale_max; scale_1++) {
            printf("%lu,", run_bench(scale_0, scale_1, nsec));
        }
        printf("\n");
    }

    return EXIT_SUCCESS;
}
