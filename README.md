# c-kzg - work in progress

The very beginnings of a simple implementation of [KZG commitments](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html) in C, using the [Blst library](https://github.com/supranational/blst) from Supranational for field and curve operations.

Initially, at least, this largely follows the [go-kzg](https://github.com/protolambda/go-kzg) implementation.

Done so far:
  - FFT and inverse FFT over the finite field.
  - FFTs over the G1 group
  - Polynomial single commitment and verification
  - Polynomial multi commitment and verification
  - [FK20](https://github.com/khovratovich/Kate/blob/master/Kate_amortized.pdf) single proof method (normal, and optimised for data availability)
  - FK20 multi proof method (normal, and optimised for data availability)
  - Polynomial extension for data availability sampling
  - Calculation of zero polynomials
  - Data recovery from samples

## Install

Build the [Blst library](https://github.com/supranational/blst) following the instructions there. Then,

1. Copy the resulting `libblst.a` file into the `lib/` directory here.
2. From Blst's `bindings/` directory copy `blst.h` and `blst_aux.h` to `inc/`

That is,

```
cp ../blst/libblast.a lib/
cp ../blst/bindings/*.h inc/
```

## Build

Build the `libckzg.a` library:

```
cd src
make lib
```

Build a debug version that aborts on error conditions and attempts to print some helpful info (file, line number, condition that failed):

```
cd src
make debuglib
```

## Run tests

```
cd src
make test
```

Unit tests for an individual file can be built and run with `make fft_fr_test` for example. Once a test runner such as *fft_fr_test* has been built, individual unit tests can be run with `./fft_fr_test <test-name>`.

Thanks to [Acutest](https://github.com/mity/acutest) for the unit test harness, which is used here under the MIT licence.

## Run benchmarks

This will run all available benchmarks, for the default one second per test size:

```
cd src
make bench
```

You can run individual benchmarks, and optionally specify how long to run each test size:

```
make fft_fr_bench
./fft_fr_bench 5
```

Doing `make clean` should resolve any weird build issues.

## Make debug builds of the tests

The default build is designed not to exit on errors, and will (should) return fairly coarse error codes for any issue. This is good for a utility library, but unhelpful for debugging. The `-DDEBUG` compiler flag  builds a version such that any assertion failure aborts the run and outputs file and line info. This is much more useful for tracking down deeply buried errors.

Each test suite can be compiled into its debug version. For example, as follows:

```
make fk20_proofs_test_debug
./fk20_proofs_test_debug fk_single_strided
```

This magic is implemented via the `CHECK` and `TRY` macros in _c_kzg.h_.

## Make documentation

`doxygen` style comments are in place throughout, although some places need more work. Build the docs in the top directory as follows:

```
doxygen Doxyfile
```

This will produce a _doc/html_ directory. Visit the _doc/html/files.html_ file in a browser to view the documentation.

## Prerequisites

 - Blst library (see above)
 - `clang` compiler. I'm using Clang 10.0.0. I'll likely add `gcc` options in future.
 - The Makefile is GNU make compatible.
 - I'm developing on Ubuntu 20.04. Will check portability later.
 - [Doxygen](https://www.doxygen.nl/index.html) for building the documentation. I'm using v1.8.17 right now.
