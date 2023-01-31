INCLUDE_DIRS = ../inc

ifeq ($(OS),Windows_NT)
	CFLAGS += -O2
else
	CFLAGS += -O2 -fPIC
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Darwin)
		CCFLAGS += -D OSX
		XCRUN = xcrun
	endif
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

test_c_kzg_4844: test_c_kzg_4844.c c_kzg_4844.c Makefile
	${CLANG_EXECUTABLE} -Wall -I$(INCLUDE_DIRS) -DFIELD_ELEMENTS_PER_BLOB=$(FIELD_ELEMENTS_PER_BLOB) -DUNIT_TESTS $(CFLAGS) -c c_kzg_4844.c -o test_c_kzg_4844.o
	${CLANG_EXECUTABLE} -Wall -I$(INCLUDE_DIRS) -DFIELD_ELEMENTS_PER_BLOB=$(FIELD_ELEMENTS_PER_BLOB) $(CFLAGS) test_c_kzg_4844.o -L ../lib -lblst -o test_c_kzg_4844 $<

test: test_c_kzg_4844
	./test_c_kzg_4844

test_c_kzg_4844_cov: test_c_kzg_4844.c c_kzg_4844.c Makefile
	@${CLANG_EXECUTABLE} -fprofile-instr-generate -fcoverage-mapping -Wall -I$(INCLUDE_DIRS) -DFIELD_ELEMENTS_PER_BLOB=$(FIELD_ELEMENTS_PER_BLOB) -DUNIT_TESTS $(CFLAGS) -c c_kzg_4844.c -o test_c_kzg_4844.o
	@${CLANG_EXECUTABLE} -fprofile-instr-generate -fcoverage-mapping -Wall -I$(INCLUDE_DIRS) -DFIELD_ELEMENTS_PER_BLOB=$(FIELD_ELEMENTS_PER_BLOB) $(CFLAGS) test_c_kzg_4844.o -L../lib -lblst -o test_c_kzg_4844 $<

test_cov: test_c_kzg_4844_cov
	@LLVM_PROFILE_FILE="ckzg.profraw" ./test_c_kzg_4844
	@$(XCRUN) llvm-profdata merge --sparse ckzg.profraw -o ckzg.profdata
	@$(XCRUN) llvm-cov show ./test_c_kzg_4844 --instr-profile=ckzg.profdata --format=html c_kzg_4844.c > coverage.html
	@$(XCRUN) llvm-cov report ./test_c_kzg_4844 --instr-profile=ckzg.profdata --show-functions c_kzg_4844.c

clean:
	rm -f  *.o test_c_kzg_4844 *.profraw *.profdata *.html
