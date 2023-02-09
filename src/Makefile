###############################################################################
# Configuration Options
###############################################################################

#
# We use clang. Some versions of GCC report missing-braces warnings.
#
CC = clang

#
# By default, this is set to the mainnet value.
#
FIELD_ELEMENTS_PER_BLOB ?= 4096

#
# The base compiler flags. More can be added on command line.
#
CFLAGS += -I../inc
CFLAGS += -Wall -Wextra -Werror -O2
CFLAGS += -DFIELD_ELEMENTS_PER_BLOB=$(FIELD_ELEMENTS_PER_BLOB)

#
# Compiler flags for including blst. Must be put after the module.
#
BLST = -L../lib -lblst

#
# Compiler flags for generating coverage data.
#
COVERAGE = -fprofile-instr-generate -fcoverage-mapping

#
# Settings for performance profiling.
#
PROFILE = -DPROFILE
PROFILER = -lprofiler
PROFILER_OPTS = CPUPROFILE_FREQUENCY=1000000000

#
# Platform specific options.
#
ifneq ($(OS),Windows_NT)
    CFLAGS += -fPIC
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        XCRUN = xcrun
        PROFILE += -L$(shell brew --prefix gperftools)/lib
        PROFILE += -I$(shell brew --prefix gperftools)/include
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

test_c_kzg_4844_prof: test_c_kzg_4844.c c_kzg_4844.c
	@$(CC) $(CFLAGS) $(PROFILE) -o $@ $< $(BLST) $(PROFILER)

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
	@LLVM_PROFILE_FILE="ckzg.profraw" ./$<
	@$(XCRUN) llvm-profdata merge --sparse ckzg.profraw -o ckzg.profdata
	@$(XCRUN) llvm-cov show --instr-profile=ckzg.profdata --format=html \
	    $< c_kzg_4844.c > coverage.html
	@$(XCRUN) llvm-cov report --instr-profile=ckzg.profdata \
	    --show-functions $< c_kzg_4844.c

.PHONY: run_profiler
run_profiler: test_c_kzg_4844_prof
	@$(PROFILER_OPTS) ./$<

.PHONY: profile_%
profile_%: run_profiler
	@echo Profiling $*...
	@pprof --pdf --nodefraction=0.0001 --edgefraction=0.0001 \
	    --focus=$* ./test_c_kzg_4844_prof $*.prof > $*.pdf

.PHONY: profile
profile: \
	profile_blob_to_kzg_commitment \
	profile_verify_kzg_proof \
	profile_verify_aggregate_kzg_proof \
	profile_compute_kzg_proof \
	profile_compute_aggregate_kzg_proof

.PHONY: clean
clean:
	@rm -f *.o *.profraw *.profdata *.html xray-log.* *.prof *.pdf \
	    test_c_kzg_4844 test_c_kzg_4844_cov test_c_kzg_4844_prof

.PHONY: format
format:
	@clang-format -i --sort-includes c_kzg_4844.* test_c_kzg_4844.c
