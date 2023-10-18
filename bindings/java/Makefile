INCLUDE_DIRS = ../../src ../../blst/bindings

TARGETS=c_kzg_4844_jni.c ../../src/c_kzg_4844.c ../../lib/libblst.a

CC_FLAGS=
OPTIMIZATION_LEVEL=-O2

ifeq ($(OS),Windows_NT)
  CLANG_EXECUTABLE=gcc
  CLANG_FLAGS=-shared
  JNI_INCLUDE_FOLDER=win32
  OS_ARCH=amd64
  LIBRARY_RESOURCE=ckzg4844jni.dll
  GRADLE_COMMAND=gradlew
else
  CLANG_EXECUTABLE=clang
  UNAME_S := $(shell uname -s)
  UNAME_M := $(shell uname -m)
  ifeq ($(UNAME_S),Linux)
    CLANG_FLAGS=-fPIC -shared
    JNI_INCLUDE_FOLDER=linux
    ifeq ($(UNAME_M),x86_64)
        OS_ARCH=amd64
    else
        OS_ARCH=$(UNAME_M)
    endif
    LIBRARY_RESOURCE=libckzg4844jni.so
  endif
  ifeq ($(UNAME_S),Darwin)
    ifeq ($(JAVA_HOME),)
      JAVA_HOME := $(shell /usr/libexec/java_home)
    endif
    CLANG_FLAGS=-dynamiclib
    JNI_INCLUDE_FOLDER=darwin
    ifeq ($(UNAME_M),arm64)
        OS_ARCH=aarch64
    else
        OS_ARCH=$(UNAME_M)
    endif
    LIBRARY_RESOURCE=libckzg4844jni.dylib
  endif
  GRADLE_COMMAND=./gradlew
endif

LIBRARY_FOLDER=src/main/resources/ethereum/ckzg4844/lib/${OS_ARCH}

ifeq ($(JAVA_HOME),)
  $(error JAVA_HOME is not set and autodetection failed)
endif

all: build test benchmark

.PHONY: build
build:
	mkdir -p ${LIBRARY_FOLDER}
	${CLANG_EXECUTABLE} ${CC_FLAGS} ${CLANG_FLAGS} ${OPTIMIZATION_LEVEL} -Wall -Wextra -Werror -Wno-missing-braces -Wno-unused-parameter -Wno-format ${addprefix -I,${INCLUDE_DIRS}} -I"${JAVA_HOME}/include" -I"${JAVA_HOME}/include/${JNI_INCLUDE_FOLDER}" -o ${LIBRARY_FOLDER}/${LIBRARY_RESOURCE} ${TARGETS}

.PHONY: test
test:
	${GRADLE_COMMAND} clean check

.PHONY: benchmark
benchmark:
	${GRADLE_COMMAND} clean jmh

