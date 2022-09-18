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
    KZGSettings ks;

    assert(C_KZG_OK == new_fft_settings(&fs, scale));

    // Allocate on the heap to avoid stack overflow for large sizes
    g1_t *s1 = malloc(fs.max_width * sizeof(g1_t));
    g2_t *s2 = malloc(fs.max_width * sizeof(g2_t));

    generate_trusted_setup(s1, s2, &secret, fs.max_width);
    assert(C_KZG_OK == new_kzg_settings(&ks, s1, s2, fs.max_width, &fs));

    poly_l p;
    assert(C_KZG_OK == new_poly_l(&p, fs.max_width));
    for (int i = 0; i < fs.max_width; i++) {
        p.values[i] = rand_fr();
    }

    fr_t x = rand_fr();
    fr_t y;
    assert(C_KZG_OK == eval_poly_l(&y, &p, &x, &fs));

    while (total_time < max_seconds * NANO) {
        g1_t proof;
        clock_gettime(CLOCK_REALTIME, &t0);

        assert(C_KZG_OK == compute_proof_single_l(&proof, &p, &x, &y, &ks));

        clock_gettime(CLOCK_REALTIME, &t1);
        nits++;
        total_time += tdiff(t0, t1);
    }

    free_poly_l(&p);
    free(s1);
    free(s2);
    free_kzg_settings(&ks);
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

    printf("*** Benchmarking KZG Proof from Lagrange, %d second%s per test.\n", nsec, nsec == 1 ? "" : "s");
    for (int scale = 1; scale <= 15; scale++) {
        printf("compute_proof_single_l/scale_%d %lu ns/op\n", scale, run_bench(scale, nsec));
    }

    return EXIT_SUCCESS;
}
