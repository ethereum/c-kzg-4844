###############################################################################
# Configuration
###############################################################################

# Platform detection.
ifeq ($(OS),Windows_NT)
	PLATFORM = Windows
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Darwin)
		PLATFORM = Darwin
	else
		PLATFORM = Linux
	endif
endif

# Some commands need xcode.
ifeq ($(PLATFORM),Darwin)
	XCRUN = xcrun
endif

# The base compiler flags. More can be added on command line.
CFLAGS += -I../inc -O2 -Wall -Wextra

# Cross-platform compilation settings.
ifeq ($(PLATFORM),Windows)
	CC = gcc
	CFLAGS += -D_CRT_SECURE_NO_WARNINGS
else
	CC = clang
	CFLAGS += -fPIC -Werror
endif

# Settings for blst.
BLST_LIBRARY = ../lib/libblst.a
BLST_BUILDSCRIPT = ../blst/build.sh
BLST_BUILDSCRIPT_FLAGS = -D__BLST_PORTABLE__

# Libraries to build with.
LIBS = $(BLST_LIBRARY)

###############################################################################
# Core
###############################################################################

all: ckzg.o test

$(BLST_BUILDSCRIPT):
	@git submodule update --init

$(BLST_LIBRARY): $(BLST_BUILDSCRIPT)
	@cd $(dir $(BLST_BUILDSCRIPT)) && \
	./$(notdir $(BLST_BUILDSCRIPT)) $(BLST_BUILDSCRIPT_FLAGS) && \
	cp $(notdir $(BLST_LIBRARY)) ../lib && \
	cp bindings/*.h ../inc

.PHONY: blst
blst: $(BLST_LIBRARY)

tests: CFLAGS += -O0
tests: tests.c $(BLST_LIBRARY)
	@$(CC) $(CFLAGS) -o $@ $< $(LIBS)

.PHONY: test
test: tests
	@./tests

###############################################################################
# Coverage
###############################################################################

tests_cov: CFLAGS += -O0 -fprofile-instr-generate -fcoverage-mapping
tests_cov: tests.c ckzg.c
	@$(CC) $(CFLAGS) -o $@ $< $(LIBS)

.PHONY: coverage
coverage: tests_cov
	@LLVM_PROFILE_FILE="ckzg.profraw" ./$<
	@$(XCRUN) llvm-profdata merge --sparse ckzg.profraw -o ckzg.profdata
	@$(XCRUN) llvm-cov show --instr-profile=ckzg.profdata --format=html \
	    $< common.c eip4844.c eip7594.c > coverage.html
	@$(XCRUN) llvm-cov report --instr-profile=ckzg.profdata \
	    --show-functions $< common.c eip4844.c eip7594.c

###############################################################################
# Profile
###############################################################################

tests_prof: LIBS += -lprofiler
tests_prof: CFLAGS += -O0 -DPROFILE
ifeq ($(PLATFORM),Darwin)
tests_prof: CFLAGS += -L$(shell brew --prefix gperftools)/lib
tests_prof: CFLAGS += -I$(shell brew --prefix gperftools)/include
endif
tests_prof: tests.c common.c eip4844.c eip7594.c
	@$(CC) $(CFLAGS) -o $@ $< $(LIBS)

.PHONY: run_profiler
run_profiler: tests_prof
	@CPUPROFILE_FREQUENCY=1000000000 ./$<

.PHONY: profile_%
profile_%: run_profiler
	@echo Profiling $*...
	@pprof --pdf --nodefraction=0.00001 --edgefraction=0.00001 \
	    ./tests_prof $*.prof > $*.pdf

.PHONY: profile
profile: \
	profile_blob_to_kzg_commitment \
	profile_compute_kzg_proof \
	profile_compute_blob_kzg_proof \
	profile_verify_kzg_proof \
	profile_verify_blob_kzg_proof \
	profile_verify_blob_kzg_proof_batch \
	profile_compute_cells_and_kzg_proofs \
	profile_recover_cells_and_kzg_proofs \
	profile_verify_cell_kzg_proof_batch

###############################################################################
# Sanitize
###############################################################################

.PHONY: sanitize_%
sanitize_%: CFLAGS += -O0 -fsanitize=$*
sanitize_%: tests.c ckzg.c
	@echo Running sanitize=$*...
	@$(CC) $(CFLAGS) -o $@ $< $(LIBS)
	@ASAN_OPTIONS=allocator_may_return_null=1 \
	    LSAN_OPTIONS=allocator_may_return_null=1 \
	    ./$@; rm $@

.PHONY: sanitize
ifeq ($(PLATFORM),Darwin)
sanitize: \
	sanitize_address \
	sanitize_undefined
else ifeq ($(PLATFORM),Linux)
sanitize: \
	sanitize_address \
	sanitize_leak \
	sanitize_safe-stack \
	sanitize_undefined
endif

###############################################################################
# Analyze
###############################################################################

.PHONY: analyze
analyze: common.c eip4844.c eip7594.c
	@$(CC) --analyze -Xanalyzer -analyzer-output=html \
	    -o analysis-report $(CFLAGS) -c $<
	@[ -d analysis-report ] && exit 1 || exit 0

###############################################################################
# Cleanup
###############################################################################

.PHONY: format
format:
	@clang-format -i --sort-includes common.* 4844.* 7594.* tests.c

.PHONY: clean
clean:
	@rm -f *.o *.profraw *.profdata *.html xray-log.* *.prof *.pdf \
	    tests tests_cov tests_prof
	@rm -rf analysis-report
