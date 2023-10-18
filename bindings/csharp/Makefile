ifeq ($(OS),Windows_NT)
	ifneq (,$(findstring Git/,$(SHELL)))
		BLST_BUILDSCRIPT = ./build.bat
	else
		BLST_BUILDSCRIPT = .\build.bat
	endif
	BLST_OBJ = blst.lib
	LOCATION ?= win-x64
	CLANG_EXECUTABLE = clang
	EXTENSION ?= ".dll"
	CKZG_LIBRARY_PATH = Ckzg.Bindings\runtimes\$(LOCATION)\native\ckzg$(EXTENSION)
	CFLAGS += -Wl,/def:ckzg.def
else
	BLST_BUILDSCRIPT = ./build.sh
	BLST_OBJ = libblst.a
	CLANG_EXECUTABLE = clang
	CFLAGS += -fPIC

	UNAME_S := $(shell uname -s)
	UNAME_M := $(shell uname -m)
	ifeq ($(UNAME_S),Linux)
		EXTENSION ?= ".so"
		ifeq ($(UNAME_M),x86_64)
			LOCATION ?= linux-x64
		else
			LOCATION ?= linux-arm64
		endif
	endif
	ifeq ($(UNAME_S),Darwin)
		EXTENSION ?= ".dylib"
		ifeq ($(UNAME_M),arm64)
			LOCATION ?= osx-arm64
		else
			LOCATION ?= osx-x64
		endif
	endif

	CKZG_LIBRARY_PATH = Ckzg.Bindings/runtimes/$(LOCATION)/native/ckzg$(EXTENSION)
endif

INCLUDE_DIRS = ../../src ../../blst/bindings
TARGETS = ckzg.c ../../src/c_kzg_4844.c ../../blst/$(BLST_OBJ)

CFLAGS += -O2 -Wall -Wextra -shared
CFLAGS += ${addprefix -I,${INCLUDE_DIRS}}
BLST_BUILDSCRIPT_FLAGS += -D__BLST_PORTABLE__
ifdef ARCH
	CFLAGS += --target=$(ARCH)
	BLST_BUILDSCRIPT_FLAGS += --target=$(ARCH)
endif

.PHONY: all
all: blst ckzg ckzg-dotnet

.PHONY: blst
blst:
	cd ../../blst && $(BLST_BUILDSCRIPT) $(BLST_BUILDSCRIPT_FLAGS)

.PHONY: ckzg
ckzg: blst
	$(CLANG_EXECUTABLE) $(CFLAGS) -o $(CKZG_LIBRARY_PATH) $(TARGETS)

.PHONY: ckzg-dotnet
ckzg-dotnet: ckzg
	dotnet build
	dotnet test
