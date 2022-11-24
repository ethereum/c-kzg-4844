# Build Shared Library

## Prerequisites

* Follow the instructions in the [README.md](../../README.md) to install blst and build the C-KZG code. 
* JAVA_HOME environment variable is set to a JDK with an `include` folder containing a jni.h file.

## Build
```bash
make c_kzg_4844_jni
```

This will install the library in the `src/main/resources/lib` folder according to your os and arch

## Test
```bash
make test
```
