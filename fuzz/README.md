# Fuzzing

This directory contains coverage-guided, differential fuzzers for the public KZG functions. It uses
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) for the heavy lifting. In `fuzz_targets`,
there is a `fuzz_<function>.rs` file for each target. These use
[`arbitrary`](https://github.com/rust-fuzz/arbitrary) for creating the inputs to the functions. We
can provide the reference tests as the starting corpus, which gives `arbitrary` a better idea of
what inputs should be. This will differentially fuzz EIP-4844 functions with
[Constantine](https://github.com/mratsim/constantine) and EIP-7594 functions with
[Rust-Eth-KZG](https://github.com/crate-crypto/rust-eth-kzg).

## Dependencies

Dependencies are `nim v1.6`, `rust`, `cargo`, and `cargo-fuzz`.

Note: this is expected to run on Linux/macOS, it is not expected to work on Windows.

### Rust dependencies

Install `rust` and `cargo` with [`rustup`](https://rustup.rs):

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then install `cargo-fuzz` like this:

```
cargo install cargo-fuzz
```

# Nim dependencies

Get and build `nim v1.6` like this:

```
git clone git@github.com:nim-lang/Nim.git
cd Nim
git checkout version-1-6
./build_all.sh
```

Then add `./bin/` to your `PATH` somehow.

## Initial corpus

Generate the initial fuzzing corpus (the reference tests) like this:

```
cargo test --features generate-fuzz-corpus
```

## Running

List available targets like this:

```
$ cargo fuzz list
fuzz_blob_to_kzg_commitment
fuzz_compute_blob_kzg_proof
fuzz_compute_cells
fuzz_compute_cells_and_kzg_proofs
fuzz_compute_kzg_proof
fuzz_recover_cells_and_kzg_proofs
fuzz_verify_blob_kzg_proof
fuzz_verify_blob_kzg_proof_batch
fuzz_verify_cell_kzg_proof_batch
fuzz_verify_kzg_proof
```

To run a fuzzer, run `cargo fuzz run fuzz_<function>` like:

```
$ cargo fuzz run fuzz_verify_blob_kzg_proof
    Finished `release` profile [optimized] target(s) in 0.05s
    Finished `release` profile [optimized] target(s) in 0.04s
     Running `fuzz/target/aarch64-apple-darwin/release/fuzz_verify_blob_kzg_proof -artifact_prefix=/Users/user/projects/c-kzg-4844/fuzz/artifacts/fuzz_verify_blob_kzg_proof/ /Users/user/projects/c-kzg-4844/fuzz/corpus/fuzz_verify_blob_kzg_proof`
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3232240354
INFO: Loaded 1 modules   (9883 inline 8-bit counters): 9883 [0x100953970, 0x10095600b),
INFO: Loaded 1 PC tables (9883 PCs): 9883 [0x100956010,0x10097c9c0),
INFO:        0 files found in /Users/user/projects/c-kzg-4844/fuzz/corpus/fuzz_verify_blob_kzg_proof
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 42 ft: 42 corp: 1/1b exec/s: 2 rss: 60Mb
#64	pulse  cov: 42 ft: 42 corp: 1/1b lim: 4 exec/s: 32 rss: 60Mb
#128	pulse  cov: 42 ft: 42 corp: 1/1b lim: 4 exec/s: 64 rss: 60Mb
#256	pulse  cov: 42 ft: 42 corp: 1/1b lim: 6 exec/s: 128 rss: 60Mb
#512	pulse  cov: 42 ft: 42 corp: 1/1b lim: 8 exec/s: 256 rss: 60Mb
#1024	pulse  cov: 42 ft: 42 corp: 1/1b lim: 14 exec/s: 512 rss: 60Mb
#2048	pulse  cov: 42 ft: 42 corp: 1/1b lim: 21 exec/s: 1024 rss: 60Mb
#4096	pulse  cov: 42 ft: 42 corp: 1/1b lim: 43 exec/s: 2048 rss: 60Mb
#8192	pulse  cov: 42 ft: 42 corp: 1/1b lim: 80 exec/s: 4096 rss: 61Mb
#16384	pulse  cov: 42 ft: 42 corp: 1/1b lim: 163 exec/s: 8192 rss: 61Mb
#32768	pulse  cov: 42 ft: 42 corp: 1/1b lim: 325 exec/s: 16384 rss: 62Mb
#65536	pulse  cov: 42 ft: 42 corp: 1/1b lim: 652 exec/s: 21845 rss: 65Mb
#131072	pulse  cov: 42 ft: 42 corp: 1/1b lim: 1300 exec/s: 32768 rss: 70Mb
...
```

To stop the fuzzer, press ctrl-C on your keyboard. It will print something like:

```
...
#65536	pulse  cov: 42 ft: 42 corp: 1/1b lim: 652 exec/s: 21845 rss: 65Mb
#131072	pulse  cov: 42 ft: 42 corp: 1/1b lim: 1300 exec/s: 32768 rss: 70Mb
^C==26722== libFuzzer: run interrupted; exiting
```

### Multithreading

If your system has multiple cores, it's easy to run fuzzers on multiple threads. Append `--jobs=<n>`
where `n` is the number of threads you would like there to be.

### Findings

If there is a crash or timeout, the fuzzer will write a file to the target directory containing the
input data associated with that crash/timeout. If this happens, please report the finding via an
issue on GitHub.