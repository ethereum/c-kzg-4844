# c-kzg - work in progress

The very beginnings of a simple implementation of [KZG commitments](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html) in C, using the [Blst library](https://github.com/supranational/blst) from Supranational for field and curve operations.

Initially, at least, this largely follows the [go-kzg](https://github.com/protolambda/go-kzg) implementation.

Done so far:
  - Rough and ready FFT and inverse FFT over the finite field.
  - Ditto for FFTs over the G1 group

## Installation

Build the [Blst library](https://github.com/supranational/blst) following the instructions there. Then,

1. Copy the resulting `libblst.a` file into the `lib/` directory here.
2. From Blst's `bindings/` directory copy `blst.h` and `blst_aux.h` to `inc/`

That is,

```
cp ../blst/libblast.a lib/
cp ../blst/bindings/*.h inc/
```

There's no library to make here yet, but you can run the tests.

## Run tests

```
cd src
make test
```

Thanks to [Acutest](https://github.com/mity/acutest) for the unit test harness, which is used here under the MIT licence.

## Prerequisites

 - Blst library (see above)
 - `clang` compiler. I'm using Clang 10.0.0. I'll likely add `gcc` options in future.
 - I'm developing on Ubuntu 20.04. Will check portability later.
 