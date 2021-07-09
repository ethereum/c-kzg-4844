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
long run_bench(int scale, int max_seconds) {
    timespec_t t0, t1;
    unsigned long total_time = 0, nits = 0;
    FFTSettings fs;

    assert(C_KZG_OK == new_fft_settings(&fs, scale));

    // Allocate on the heap to avoid stack overflow for large sizes
    uint64_t *missing = malloc(fs.max_width * sizeof(uint64_t));
    for (int i = 0; i < fs.max_width; i++) {
        missing[i] = i;
    }
    shuffle(missing, fs.max_width);

    fr_t *zero_eval = malloc(fs.max_width * sizeof(fr_t));
    fr_t *zero_poly = malloc(fs.max_width * sizeof(fr_t));
    poly zero_poly_p;
    zero_poly_p.coeffs = zero_poly;
    zero_poly_p.length = fs.max_width;
    while (total_time < max_seconds * NANO) {
        clock_gettime(CLOCK_REALTIME, &t0);
        // Half missing leaves enough FFT computation space
        assert(C_KZG_OK == zero_polynomial_via_multiplication(zero_eval, &zero_poly_p, fs.max_width, missing,
                                                              fs.max_width / 2, &fs));
        clock_gettime(CLOCK_REALTIME, &t1);
        nits++;
        total_time += tdiff(t0, t1);
    }

    free_poly(&zero_poly_p);
    free(zero_eval);
    free(missing);
    free_fft_settings(&fs);

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

    printf("*** Benchmarking Zero Polynomial, %d second%s per test.\n", nsec, nsec == 1 ? "" : "s");
    for (int scale = 5; scale <= 15; scale++) {
        printf("zero_poly/scale_%d %lu ns/op\n", scale, run_bench(scale, nsec));
    }

    return EXIT_SUCCESS;
}
