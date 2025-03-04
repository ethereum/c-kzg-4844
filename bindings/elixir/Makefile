CC = clang
PRIV_DIR = $(MIX_APP_PATH)/priv
SRC_ROOT = $(shell pwd)
C_SRC = $(SRC_ROOT)/native/src

CFLAGS += -Wall -Wextra -shared -std=c11 -fPIC -I"$(ERTS_INCLUDE_DIR)"
UNAME_S := $(shell uname -s)
ifndef TARGET_ABI
ifeq ($(UNAME_S),Darwin)
	TARGET_ABI = darwin
endif
endif

ifeq ($(TARGET_ABI),darwin)
	CFLAGS += -undefined dynamic_lookup -flat_namespace
endif

ifeq ($(OS),Windows_NT)
	ifneq (,$(findstring Git/,$(SHELL)))
		BLST_BUILDSCRIPT = ./build.bat
	else
		BLST_BUILDSCRIPT = .\build.bat
	endif
	BLST_OBJ = blst.lib
	LOCATION ?= win-x64
	EXTENSION ?= ".dll"
	CKZG_LIBRARY_PATH = $(PRIV_DIR)/ckzg_nif$(EXTENSION)
else
	BLST_BUILDSCRIPT = ./build.sh
	BLST_OBJ = libblst.a
	CFLAGS += -fPIC
	EXTENSION ?= ".so"

	UNAME_S := $(shell uname -s)
	UNAME_M := $(shell uname -m)
	ifeq ($(UNAME_S),Linux)
		ifeq ($(UNAME_M),x86_64)
			LOCATION ?= linux-x64
		else
			LOCATION ?= linux-arm64
		endif
	endif
	ifeq ($(UNAME_S),Darwin)
		ifeq ($(UNAME_M),arm64)
			LOCATION ?= osx-arm64
		else
			LOCATION ?= osx-x64
		endif
	endif

	CKZG_LIBRARY_PATH = $(PRIV_DIR)/ckzg_nif$(EXTENSION)
endif

INCLUDE_DIRS = ../../src ../../blst/bindings $(ERTS_INCLUDE_DIR)
TARGETS = $(C_SRC)/ckzg_wrap.c ../../src/ckzg.c ../../blst/$(BLST_OBJ)

CFLAGS += ${addprefix -I,${INCLUDE_DIRS}}
BLST_BUILDSCRIPT_FLAGS += -D__BLST_PORTABLE__
ifdef ARCH
	CFLAGS += --target=$(ARCH)
	BLST_BUILDSCRIPT_FLAGS += --target=$(ARCH)
endif

ifdef DEBUG
	CFLAGS += -g
else
	CFLAGS += -O2
endif

.PHONY: all
all: blst ckzg

.PHONY: blst
blst:
	$(MAKE) -C ../../src blst

.PHONY: ckzg
ckzg: blst
	$(CC) $(CFLAGS) -o $(CKZG_LIBRARY_PATH) $(TARGETS)
	@echo "$(CC_PRECOMPILER_CURRENT_TARGET)" > "$(PRIV_DIR)/build.txt"
