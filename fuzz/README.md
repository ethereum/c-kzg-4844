# Fuzzing

This directory contains coverage-guided fuzzers for KZG functions. It uses
LLVM's [libFuzzer](https://llvm.org/docs/LibFuzzer.html) for the heavy lifting.
Each directory is named after a target and contains a single file (`fuzz.c`)
that implements a `LLVMFuzzerTestOneInput` function. These are relatively
simple; if the input matches the size requirements, it passes the data to the
target function. There is a Makefile that compiles and starts the fuzzer, which
means it should be pretty easy.

## Dependencies

This is expected to run on Linux/macOS, it is not expected to work on Windows.
In addition to `build-essentials` and `clang`, this requires `llvm` to be
installed:

### Linux

```
sudo apt install llvm
```

### macOS

```
brew install llvm
```

## Targets

Currently, only the public KZG interface functions are fuzzable:
```
$ make
Available targets:
 - fuzz_blob_to_kzg_commitment
 - fuzz_compute_blob_kzg_proof
 - fuzz_compute_kzg_proof
 - fuzz_verify_blob_kzg_proof
 - fuzz_verify_blob_kzg_proof_batch
 - fuzz_verify_kzg_proof
```

To run a fuzzer, run `make fuzz_<func>` like:

```
$ make fuzz_verify_kzg_proof
[+] Building blst
+ cc -O2 -fno-builtin -fPIC -Wall -Wextra -Werror -c ./src/server.c
+ cc -O2 -fno-builtin -fPIC -Wall -Wextra -Werror -c ./build/assembly.S
+ ar rc libblst.a assembly.o server.o
[+] Generating corpus
[+] Compiling verify_kzg_proof fuzzer
[+] Starting verify_kzg_proof fuzzer
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 855755358
INFO: Loaded 1 modules   (228 inline 8-bit counters): 228 [0x1025a00f8, 0x1025a01dc), 
INFO: Loaded 1 PC tables (228 PCs): 228 [0x1025a01e0,0x1025a1020), 
INFO:        1 files found in ./verify_kzg_proof/corpus
INFO: seed corpus: files: 1 min: 160b max: 160b total: 160b rss: 28Mb
#2      pulse  ft: 17 exec/s: 1 rss: 29Mb
#2      INITED cov: 17 ft: 17 corp: 1/160b exec/s: 1 rss: 29Mb
#4      pulse  cov: 17 ft: 17 corp: 1/160b lim: 160 exec/s: 2 rss: 29Mb
#5      NEW    cov: 19 ft: 20 corp: 2/320b lim: 160 exec/s: 2 rss: 29Mb L: 160/160 MS: 3 ChangeASCIIInt-ChangeBit-ChangeBit-
#7      NEW    cov: 20 ft: 21 corp: 3/477b lim: 160 exec/s: 3 rss: 29Mb L: 157/160 MS: 2 ChangeByte-EraseBytes-
#8      pulse  cov: 20 ft: 21 corp: 3/477b lim: 160 exec/s: 4 rss: 29Mb
#13     NEW    cov: 21 ft: 23 corp: 4/637b lim: 160 exec/s: 6 rss: 29Mb L: 160/160 MS: 1 ChangeBit-
#16     pulse  cov: 21 ft: 23 corp: 4/637b lim: 160 exec/s: 8 rss: 29Mb
...
```

There are a few steps:

* Build the blst library.
* Generate initial corpora files.
* Compile the fuzzer.
* Start the fuzzer.

Reference [this page](https://llvm.org/docs/LibFuzzer.html#output) for a guide on reading the output.

To stop the fuzzer, press ctrl-C on your keyboard. It will print something like:

```
...
#65536  pulse  cov: 25 ft: 29 corp: 7/961b lim: 160 exec/s: 16384 rss: 29Mb
#131072 pulse  cov: 25 ft: 29 corp: 7/961b lim: 160 exec/s: 18724 rss: 29Mb
^C==11616== libFuzzer: run interrupted; exiting
make: [run_fuzz_verify_kzg_proof] Error 72 (ignored)
```

If your system has multiple cores, it's easy to run fuzzers on multiple threads.
Append `THREADS=<n>` where `n` is the number of threads you would like there to
be. If you wish to use all available CPU cores, specify `-1` as the count.

```
$ make fuzz_verify_kzg_proof THREADS=4
[+] Starting verify_kzg_proof fuzzer
./verify_kzg_proof/fuzz -artifact_prefix=./verify_kzg_proof/ -max_len=160 ./verify_kzg_proof/corpus >fuzz-0.log 2>&1
./verify_kzg_proof/fuzz -artifact_prefix=./verify_kzg_proof/ -max_len=160 ./verify_kzg_proof/corpus >fuzz-2.log 2>&1
./verify_kzg_proof/fuzz -artifact_prefix=./verify_kzg_proof/ -max_len=160 ./verify_kzg_proof/corpus >fuzz-1.log 2>&1
./verify_kzg_proof/fuzz -artifact_prefix=./verify_kzg_proof/ -max_len=160 ./verify_kzg_proof/corpus >fuzz-3.log 2>&1
```

When you press ctrl-C it will stop all the fuzzers and print their output to
your console sequentially. You will most likely need to scroll up to see their
outputs.

When operating in parallel (threads) the fuzzers use a shared corpus and are
intelligent enough to learn from other threads that have progressed further.
When you see a line that starts with "RELOAD" that fuzzer process is updating
its corpus with findings from other threads.

### Findings

If there is a crash or timeout, the fuzzer will write a file to the target
directory containing the input data associated with that crash/timeout. If this
happens, please report the finding via an issue on GitHub.
