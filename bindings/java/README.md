# Build Shared Library

## Prerequisites

* Follow the instructions in the [README.md](../../README.md) to install blst and C-KZG. 
* JAVA_HOME environment variable is set to a JDK with an `include` folder containing a jni.h file.

## Windows

```bat
TBC
```

## Linux

```bash
clang -O -Wall -shared -fPIC -I../../blst/bindings -I../../src/ -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -o lib/libckzg4844jni.so c_kzg_4844_jni.c c_kzg_4844.o ../../lib/libblst.a
```

## Mac-OS

```bash
TBC
```
