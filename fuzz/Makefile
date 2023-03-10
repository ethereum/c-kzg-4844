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

# Default to 1 thread, to use all cores specify -1.
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
# Makefile Rules
###############################################################################

$(LIBBLST):
	@echo [+] Building blst
	@make -C../src blst

.PRECIOUS: %/corpus
%/corpus:
	@echo [+] Generating corpus
	@mkdir -p $@
	@cd gen_corpus && go run .

.PRECIOUS: %/fuzz
%/fuzz: %/fuzz.c ../src/c_kzg_4844.c %/corpus $(LIBBLST)
	@echo [+] Compiling $* fuzzer
	@$(ENV_OPTS) $(CC) $(CFLAGS) -o $@ $< $(BLST)

.PHONY: fuzz_%
fuzz_%: %/fuzz
	@echo [+] Starting $* fuzzer
	@-./$< \
		-artifact_prefix=./$*/ \
		-workers=$(THREADS) \
		-jobs=$(THREADS) \
		./$*/corpus