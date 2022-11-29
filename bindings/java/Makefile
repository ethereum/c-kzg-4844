INCLUDE_DIRS = ../../src ../../blst/bindings

LIBRARY_FOLDER=src/main/resources/ethereum/ckzg4844/lib

CC_FLAGS=

ifeq ($(OS),Windows_NT)
	CLANG_EXECUTABLE=clang
	GRADLE_COMMAND=gradlew
	CLANG_FLAGS=-shared
	JNI_INCLUDE_FOLDER=win32
	OS_ARCH=amd64
	LIBRARY_RESOURCE=ckzg4844jni.dll
else
	CLANG_EXECUTABLE=clang
	GRADLE_COMMAND=./gradlew
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
endif

ifeq ($(JAVA_HOME),)
	$(error JAVA_HOME is not set and autodetection failed)
endif

all: build test

build:
	mkdir -p ${LIBRARY_FOLDER}/${OS_ARCH}
	${CLANG_EXECUTABLE} ${CC_FLAGS} ${CLANG_FLAGS} -O -Wall ${addprefix -I,${INCLUDE_DIRS}} -I"${JAVA_HOME}/include" -I"${JAVA_HOME}/include/${JNI_INCLUDE_FOLDER}" -o ${LIBRARY_FOLDER}/${OS_ARCH}/${LIBRARY_RESOURCE} c_kzg_4844_jni.c c_kzg_4844.o ../../lib/libblst.a

test:
	${GRADLE_COMMAND} clean test

