# Java binding

## Build shared library

### Prerequisites

* Follow the instructions in the [README.md](../../README.md) to build blst.
* `JAVA_HOME` environment variable is set to a JDK with an `include` folder containing a `jni.h`
  file.

### Build

```bash
make build
```

This will install the shared library in `src/main/resources/ethereum/ckzg4844/lib` with a folder
structure
and name according to the preset selected (mainnet or minimal) and your OS.

All variables which could be passed to the `make` command and the defaults can be found in
the [Makefile](./Makefile).

## Test

```bash
make test
```

## Benchmark

JMH is used for benchmarking.
See [CKZG4844JNIBenchmark.java](src/jmh/java/ethereum/ckzg4844/CKZG4844JNIBenchmark.java) for more
information.

```bash
make benchmark
```

## Library

The library which uses this binding and publishes a package to a public maven repo
is [jc-kzg-4844](https://github.com/ConsenSys/jc-kzg-4844).