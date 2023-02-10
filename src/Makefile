###############################################################################
# Configuration Options
###############################################################################

# We use clang. Some versions of GCC report missing-braces warnings.
CC = clang

# By default, this is set to the mainnet value.
FIELD_ELEMENTS_PER_BLOB ?= 4096

# The base compiler flags. More can be added on command line.
CFLAGS += -I../inc
CFLAGS += -Wall -Wextra -Werror -O2
CFLAGS += -DFIELD_ELEMENTS_PER_BLOB=$(FIELD_ELEMENTS_PER_BLOB)

# Compiler flags for including blst. Put after source files.
BLST = -L../lib -lblst

# Compiler flags for generating coverage data.
COVERAGE = -fprofile-instr-generate -fcoverage-mapping

# Platform specific options.
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
	@$(CC) $(CFLAGS) -c $<

test_c_kzg_4844: test_c_kzg_4844.c c_kzg_4844.c
	@$(CC) $(CFLAGS) -o $@ $< $(BLST) 

test_c_kzg_4844_cov: test_c_kzg_4844.c c_kzg_4844.c
	@$(CC) $(CFLAGS) $(COVERAGE) -o $@ $< $(BLST) 

.PHONY: blst
blst:
	@cd ../blst && \
	./build.sh && \
	cp libblst.a ../lib && \
	cp bindings/*.h ../inc

.PHONY: test
test: test_c_kzg_4844
	@./test_c_kzg_4844

.PHONY: test_cov
test_cov: test_c_kzg_4844_cov
	@LLVM_PROFILE_FILE="ckzg.profraw" ./test_c_kzg_4844_cov
	@$(XCRUN) llvm-profdata merge --sparse ckzg.profraw -o ckzg.profdata
	@$(XCRUN) llvm-cov show --instr-profile=ckzg.profdata --format=html \
	    $< c_kzg_4844.c > coverage.html
	@$(XCRUN) llvm-cov report --instr-profile=ckzg.profdata \
	    --show-functions $< c_kzg_4844.c

.PHONY: clean
clean:
	@rm -f *.o *.profraw *.profdata *.html \
	    test_c_kzg_4844 test_c_kzg_4844_cov

.PHONY: format
format:
	@clang-format -i --sort-includes c_kzg_4844.* test_c_kzg_4844.c
