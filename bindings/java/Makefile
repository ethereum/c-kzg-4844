INCLUDE_DIRS = ../../src ../../blst/bindings

ifeq ($(OS),Windows_NT)
	CLANG_EXECUTABLE=gcc
	CLANG_FLAGS=-shared
	JNI_INCLUDE_FOLDER=win32
	LIBRARY_RESOURCE=ckzg4844jni.dll
	GRADLE_COMMAND=gradlew
else
	CLANG_EXECUTABLE=clang
    GRADLE_COMMAND=./gradlew
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		CLANG_FLAGS=-fPIC -shared
    	JNI_INCLUDE_FOLDER=linux
    	LIBRARY_RESOURCE=libckzg4844jni.so
	endif
	ifeq ($(UNAME_S),Darwin)
		CLANG_FLAGS=-dynamiclib
    	JNI_INCLUDE_FOLDER=darwin
    	LIBRARY_RESOURCE=libckzg4844jni.dylib
	endif
endif

c_kzg_4844_jni:
	${CLANG_EXECUTABLE} ${CLANG_FLAGS} -O -Wall ${addprefix -I,${INCLUDE_DIRS}} -I"${JAVA_HOME}/include" -I"${JAVA_HOME}/include/${JNI_INCLUDE_FOLDER}" -o src/main/resources/lib/${LIBRARY_RESOURCE} c_kzg_4844_jni.c c_kzg_4844.o ../../lib/libblst.a

test:
	${GRADLE_COMMAND} clean test


