# Java Bindings for the C-KZG Library

This directory contains Java bindings for the C-KZG-4844 library.

## Prerequisites

* Build blst by running `make blst` in the [library source directory](../../src).
* Set `JAVA_HOME` environment variable to a JDK with an `include` folder containing a `jni.h` file.

## Build

```bash
make build
```

This will install the shared library in `src/main/resources/ethereum/ckzg4844/lib` with a folder
structure and name according to your OS.

All variables which could be passed to the `make` command and the defaults can be found in
the [Makefile](./Makefile).

## Test

```bash
make test
```

## Public Maven Repo

The library which uses this binding and publishes a package to a [public maven repo](https://central.sonatype.com/artifact/io.consensys.protocols/jc-kzg-4844)
is [jc-kzg-4844](https://github.com/ConsenSys/jc-kzg-4844).
