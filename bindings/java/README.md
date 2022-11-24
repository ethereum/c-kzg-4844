# Build Shared Library

## Prerequisites

* Follow the instructions in the home README.md to create the libblst.a. 
* JAVA_HOME environment variable is set to a jdk with an `include` folder containing jni.h file.

## Windows

```bat
TBC
```

## Linux

```bash
clang -O -Wall -shared -fPIC -I../../blst/bindings -I../../src/ -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -o lib/libckzg4844jni.so c_kzg_4844_jni.c ../../src/c_kzg_4844.c ../../blst/libblst.a
```

## Mac-OS

```bash
TBC
```
