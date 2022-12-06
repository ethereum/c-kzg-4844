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
  ifeq ($(UNAME_S),Linux)
    CLANG_FLAGS=-fPIC -shared
    JNI_INCLUDE_FOLDER=linux
    OS_ARCH=amd64
    LIBRARY_RESOURCE=libckzg4844jni.so
  endif
  ifeq ($(UNAME_S),Darwin)
    ifeq ($(JAVA_HOME),)
      JAVA_HOME := $(shell /usr/libexec/java_home)
    endif
    CLANG_FLAGS=-dynamiclib
    JNI_INCLUDE_FOLDER=darwin
    OS_ARCH=x86_64
    LIBRARY_RESOURCE=libckzg4844jni.dylib
  endif
  GRADLE_COMMAND=./gradlew
endif

PRESET ?= mainnet

ifeq ($(PRESET),minimal)
  FIELD_ELEMENTS_PER_BLOB ?= 4
else
  FIELD_ELEMENTS_PER_BLOB ?= 4096
endif

LIBRARY_FOLDER=src/main/resources/ethereum/ckzg4844/lib/${OS_ARCH}/${PRESET}

ifeq ($(JAVA_HOME),)
  $(error JAVA_HOME is not set and autodetection failed)
endif

all: build test benchmark

build:
	mkdir -p ${LIBRARY_FOLDER}
	${CLANG_EXECUTABLE} ${CC_FLAGS} ${CLANG_FLAGS} ${OPTIMIZATION_LEVEL} -Wall -Wno-missing-braces ${addprefix -I,${INCLUDE_DIRS}} -I"${JAVA_HOME}/include" -I"${JAVA_HOME}/include/${JNI_INCLUDE_FOLDER}" -DFIELD_ELEMENTS_PER_BLOB=${FIELD_ELEMENTS_PER_BLOB} -o ${LIBRARY_FOLDER}/${LIBRARY_RESOURCE} ${TARGETS}

test:
	${GRADLE_COMMAND} clean test

benchmark:
	${GRADLE_COMMAND} clean jmh

