INCLUDE_DIRS = ../inc

ifeq ($(OS),Windows_NT)
	CFLAGS += -O2
else
	CFLAGS += -O2 -fPIC
endif

CLANG_EXECUTABLE=clang
BLST_BUILD_SCRIPT=./build.sh

all: c_kzg_4844.o lib

c_kzg_4844.o: c_kzg_4844.c Makefile
	${CLANG_EXECUTABLE} -Wall -I$(INCLUDE_DIRS) $(CFLAGS) -c $<

# Will fail with "patch does not apply" if it has already been patched.
# Safe to ignore.
blst:
	cd ../blst; \
	git apply < ../blst_sha.patch; \
	${BLST_BUILD_SCRIPT} && \
	cp libblst.a ../lib && \
	cp bindings/*.h ../inc

# Make sure c_kzg_4844.o is built and copy it for the NodeJS and Java bindings
lib: c_kzg_4844.o Makefile
	cp *.o ../bindings/node.js
	cp *.o ../bindings/java
