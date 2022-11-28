# Build Shared Library

## Prerequisites

* Follow the instructions in the [README.md](../../README.md) to build blst and the C-KZG library.
* `JAVA_HOME` environment variable is set to a JDK with an `include` folder containing a `jni.h` file.

## Build
```bash
make build
```

This will install the library in the `src/main/resources/ethereum/ckzg4844/lib` folder with a name according to your OS

## Test
```bash
make test
```
