###############################################################################
# Configuration Options
###############################################################################

CC = clang

FIELD_ELEMENTS_PER_BLOB ?= 4096

CFLAGS += -I../inc
CFLAGS += -Wall -Wextra -Werror -O0
CFLAGS += -DFIELD_ELEMENTS_PER_BLOB=$(FIELD_ELEMENTS_PER_BLOB)
CFLAGS += -g -fsanitize=fuzzer

BLST = -L../lib -lblst
LIBBLST = ../lib/libblst.a

# Default to no threads, to use all cores specify -1.
THREADS ?= 0
ifeq ($(THREADS), -1)
override THREADS = $(shell nproc --all)
endif

# On macOS, you need to use clang from the llvm package.
ifneq ($(OS),Windows_NT)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
ENV_OPTS += PATH=$(shell brew --prefix llvm)/bin:$(PATH)
endif
endif

###############################################################################
# Helper targets
###############################################################################

.PHONY: targets
targets:
	@echo Available targets:
	@# List targets | filter fuzz targets | remove deps | add prefix
	@make -qp | grep "^fuzz_" | sed 's/:.*//' | sed 's/^/ - /' | sort | uniq

$(LIBBLST):
	@echo [+] Building blst
	@make -C../src blst

.PRECIOUS: %/corpus
%/corpus:
	@echo [+] Generating corpus
	@cd gen_corpus && go run .

.PRECIOUS: %/fuzz
%/fuzz: %/fuzz.c ../src/c_kzg_4844.c %/corpus $(LIBBLST)
	@echo [+] Compiling $* fuzzer
	@$(ENV_OPTS) $(CC) $(CFLAGS) -o $@ $< $(BLST)

.PHONY: run_fuzz_%
run_fuzz_%: %/fuzz
	@echo [+] Starting $* fuzzer
	@-./$< \
		-artifact_prefix=./$*/ \
		-workers=$(THREADS) \
		-jobs=$(THREADS) \
		-max_len=$(LEN) \
		./$*/corpus

###############################################################################
# Fuzzing targets
###############################################################################

# Length is (4096 * 32).
fuzz_blob_to_kzg_commitment: LEN=131072
fuzz_blob_to_kzg_commitment: run_fuzz_blob_to_kzg_commitment

# Length is (4096 * 32) + 32.
fuzz_compute_kzg_proof: LEN=131104
fuzz_compute_kzg_proof: run_fuzz_compute_kzg_proof

# Length is (4096 * 32) + 48.
fuzz_compute_blob_kzg_proof: LEN=131120
fuzz_compute_blob_kzg_proof: run_fuzz_compute_blob_kzg_proof

# Length is 48 + 32 + 32 + 48.
fuzz_verify_kzg_proof: LEN=160
fuzz_verify_kzg_proof: run_fuzz_verify_kzg_proof

# Length is (4096 * 32) + 48 + 48.
fuzz_verify_blob_kzg_proof: LEN=131168
fuzz_verify_blob_kzg_proof: run_fuzz_verify_blob_kzg_proof

# Length is (3 * 4096 * 32) + (3 * 48) + (3 * 48).
fuzz_verify_blob_kzg_proof_batch: LEN=393504
fuzz_verify_blob_kzg_proof_batch: run_fuzz_verify_blob_kzg_proof_batch
