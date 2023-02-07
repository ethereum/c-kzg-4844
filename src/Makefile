###############################################################################
# Configuration Options
###############################################################################

CC=clang
FIELD_ELEMENTS_PER_BLOB?=4096

#
# Gather the compiler flags.
#
CFLAGS += -I../inc
CFLAGS += -Wall -Wextra -Werror -O2
CFLAGS += -DFIELD_ELEMENTS_PER_BLOB=$(FIELD_ELEMENTS_PER_BLOB)

#
# Compiler flags for specific actions.
#
BLST = -L../lib -lblst
TEST = -DUNIT_TESTS
COVERAGE = -fprofile-instr-generate -fcoverage-mapping

#
# Platform specific options.
#
ifneq ($(OS),Windows_NT)
    CFLAGS += -fPIC
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        XCRUN = xcrun
    endif
endif

###############################################################################
# Makefile Rules
###############################################################################

all: c_kzg_4844.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<

test_c_kzg_4844: test_c_kzg_4844.c c_kzg_4844.c
	$(CC) $(CFLAGS) $(BLST) $(TEST) -o $@ $^

test_c_kzg_4844_cov: test_c_kzg_4844.c c_kzg_4844.c
	$(CC) $(CFLAGS) $(BLST) $(COVERAGE) $(TEST) -o $@ $^

.PHONY: blst
blst:
	cd ../blst; \
	./build.sh && \
	cp libblst.a ../lib && \
	cp bindings/*.h ../inc

.PHONY: test
test: test_c_kzg_4844
	./test_c_kzg_4844

.PHONY: test_cov
test_cov: test_c_kzg_4844_cov
	LLVM_PROFILE_FILE="ckzg.profraw" ./test_c_kzg_4844_cov
	$(XCRUN) llvm-profdata merge --sparse ckzg.profraw -o ckzg.profdata
	$(XCRUN) llvm-cov show ./test_c_kzg_4844_cov \
            --instr-profile=ckzg.profdata --format=html \
            c_kzg_4844.c > coverage.html
	$(XCRUN) llvm-cov report ./test_c_kzg_4844_cov \
            --instr-profile=ckzg.profdata --show-functions c_kzg_4844.c

.PHONY: clean
clean:
	rm -f  *.o test_c_kzg_4844 *.profraw *.profdata *.html

.PHONY: format
format:
	clang-format -i --sort-includes c_kzg_4844.* test_c_kzg_4844.c
