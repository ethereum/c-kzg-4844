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

# Disable optimizations. Put after $CFLAGS.
NO_OPTIMIZE = -O0

# Settings for blst.
BLST_LIBRARY = ../lib/libblst.a
BLST_BUILDSCRIPT = ../blst/build.sh
BLST = -L../lib -lblst

# Compiler flags for generating coverage data.
COVERAGE = -fprofile-instr-generate -fcoverage-mapping

# Settings for performance profiling.
PROFILE = -DPROFILE
PROFILER = -lprofiler
PROFILER_OPTS = CPUPROFILE_FREQUENCY=1000000000

# Platform specific options.
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

all: c_kzg_4844.o test

$(BLST_BUILDSCRIPT):
	@git submodule update --init

$(BLST_LIBRARY): $(BLST_BUILDSCRIPT)
	@cd $(dir $(BLST_BUILDSCRIPT)) && \
	./$(notdir $(BLST_BUILDSCRIPT)) && \
	cp $(notdir $(BLST_LIBRARY)) ../lib && \
	cp bindings/*.h ../inc

.PHONY: blst
blst: $(BLST_LIBRARY)

c_kzg_4844.o: c_kzg_4844.c $(BLST_LIBRARY)
	@$(CC) $(CFLAGS) -c $<

test_c_kzg_4844: test_c_kzg_4844.c c_kzg_4844.c
	@$(CC) $(CFLAGS) $(NO_OPTIMIZE) -o $@ $< $(BLST)

test_c_kzg_4844_cov: test_c_kzg_4844.c c_kzg_4844.c
	@$(CC) $(CFLAGS) $(NO_OPTIMIZE) $(COVERAGE) -o $@ $< $(BLST)

test_c_kzg_4844_prof: test_c_kzg_4844.c c_kzg_4844.c
	@$(CC) $(CFLAGS) $(NO_OPTIMIZE) $(PROFILE) -o $@ $< $(BLST) $(PROFILER)

.PHONY: test
test: test_c_kzg_4844
	@./test_c_kzg_4844

.PHONY: coverage
coverage: test_c_kzg_4844_cov
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
	@pprof --pdf --nodefraction=0.00001 --edgefraction=0.00001 \
	    ./test_c_kzg_4844_prof $*.prof > $*.pdf

.PHONY: profile
profile: \
	profile_blob_to_kzg_commitment \
	profile_compute_kzg_proof \
	profile_compute_blob_kzg_proof \
	profile_verify_kzg_proof \
	profile_verify_blob_kzg_proof \
	profile_verify_blob_kzg_proof_batch

.PHONY: sanitize_%
sanitize_%: test_c_kzg_4844.c c_kzg_4844.c
	@echo Running sanitize=$*...
	@$(CC) $(CFLAGS) $(NO_OPTIMIZE) -fsanitize=$* -o $@ $< $(BLST)
	@ASAN_OPTIONS=allocator_may_return_null=1 \
	 LSAN_OPTIONS=allocator_may_return_null=1 \
	 ./$@; rm $@

ifneq ($(OS),Windows_NT)
UNAME_S := $(shell uname -s)
.PHONY: sanitize
ifeq ($(UNAME_S),Darwin)
sanitize: \
	sanitize_address \
	sanitize_undefined
else
sanitize: \
	sanitize_address \
	sanitize_leak \
	sanitize_safe-stack \
	sanitize_undefined
endif
endif

.PHONY: analyze
analyze: c_kzg_4844.c
	@$(CC) --analyze -Xanalyzer -analyzer-output=html \
	    -o analysis-report $(CFLAGS) -c $<
	@[ -d analysis-report ] && exit 1 || exit 0

.PHONY: clean
clean:
	@rm -f *.o *.profraw *.profdata *.html xray-log.* *.prof *.pdf \
	    test_c_kzg_4844 test_c_kzg_4844_cov test_c_kzg_4844_prof
	@rm -rf analysis-report

.PHONY: format
format:
	@clang-format -i --sort-includes c_kzg_4844.* test_c_kzg_4844.c
