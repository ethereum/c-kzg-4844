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
    fr_t *poly = malloc(fs.max_width * sizeof(fr_t));
    for (int i = 0; i < fs.max_width / 2; i++) {
        fr_from_uint64(&poly[i], i);
    }
    for (int i = fs.max_width / 2; i < fs.max_width; i++) {
        poly[i] = fr_zero;
    }

    fr_t *data = malloc(fs.max_width * sizeof(fr_t));
    assert(C_KZG_OK == fft_fr(data, poly, false, fs.max_width, &fs));

    fr_t *samples = malloc(fs.max_width * sizeof(fr_t));
    for (int i = 0; i < fs.max_width; i++) {
        samples[i] = data[i];
    }

    // randomly zero out half of the points
    for (int i = 0; i < fs.max_width / 2; i++) {
        int j = rand() % fs.max_width;
        while (fr_is_null(&samples[j])) j = rand() % fs.max_width;
        samples[j] = fr_null;
    }

    fr_t *recovered = malloc(fs.max_width * sizeof(fr_t));
    while (total_time < max_seconds * NANO) {
        clock_gettime(CLOCK_REALTIME, &t0);
        assert(C_KZG_OK == recover_poly_from_samples(recovered, samples, fs.max_width, &fs));
        clock_gettime(CLOCK_REALTIME, &t1);

        // Verify the result is correct
        for (int i = 0; i < fs.max_width; i++) {
            assert(fr_equal(&data[i], &recovered[i]));
        }

        nits++;
        total_time += tdiff(t0, t1);
    }

    free(recovered);
    free(samples);
    free(data);
    free(poly);
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

    printf("*** Benchmarking Recover From Samples, %d second%s per test.\n", nsec, nsec == 1 ? "" : "s");
    for (int scale = 5; scale <= 15; scale++) {
        printf("recover/scale_%d %lu ns/op\n", scale, run_bench(scale, nsec));
    }

    return EXIT_SUCCESS;
}
