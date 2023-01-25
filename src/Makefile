INCLUDE_DIRS = ../inc

ifeq ($(OS),Windows_NT)
	CFLAGS += -O2
else
	CFLAGS += -O2 -fPIC
endif

CLANG_EXECUTABLE=clang
BLST_BUILD_SCRIPT=./build.sh
FIELD_ELEMENTS_PER_BLOB?=4096

all: c_kzg_4844.o lib

# If you change FIELD_ELEMENTS_PER_BLOB, remember to rm c_kzg_4844.o and make again
c_kzg_4844.o: c_kzg_4844.c Makefile
	${CLANG_EXECUTABLE} -Wall -I$(INCLUDE_DIRS) -DFIELD_ELEMENTS_PER_BLOB=$(FIELD_ELEMENTS_PER_BLOB) $(CFLAGS) -c $<

blst:
	cd ../blst; \
	${BLST_BUILD_SCRIPT} && \
	cp libblst.a ../lib && \
	cp bindings/*.h ../inc

# Make sure c_kzg_4844.o is built and copy it for the NodeJS bindings
lib: c_kzg_4844.o Makefile
	cp *.o ../bindings/node.js
