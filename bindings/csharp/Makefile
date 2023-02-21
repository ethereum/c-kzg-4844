ifeq ($(OS),Windows_NT)
    BLST_BUILDSCRIPT = ./build.bat
    BLST_OBJ = blst.lib
    CSHARP_PLATFORM ?= win-x64
    CLANG_EXECUTABLE = clang
    CKZG_LIBRARY_PATH = Ckzg.Bindings\runtimes\$(CSHARP_PLATFORM)\native\ckzg.dll
else
    BLST_BUILDSCRIPT = ./build.sh
    BLST_OBJ = libblst.a
    CLANG_EXECUTABLE = clang

    UNAME_S := $(shell uname -s)
    UNAME_M := $(shell uname -m)
    ifeq ($(UNAME_S),Linux)
        ifeq ($(UNAME_M),x86_64)
            CSHARP_PLATFORM ?= linux-x64
        else
            CSHARP_PLATFORM ?= linux-arm64
        endif
    endif
    ifeq ($(UNAME_S),Darwin)
        ifeq ($(UNAME_M),arm64)
            CSHARP_PLATFORM ?= osx-arm64
        else
            CSHARP_PLATFORM ?= osx-x64
        endif
    endif

    CKZG_LIBRARY_PATH = Ckzg.Bindings/runtimes/$(CSHARP_PLATFORM)/native/ckzg.so
endif

FIELD_ELEMENTS_PER_BLOB ?= 4096
INCLUDE_DIRS = ../../src ../../blst/bindings
TARGETS = ckzg.c ../../src/c_kzg_4844.c ../../blst/$(BLST_OBJ)

CFLAGS += -O2 -Wall -Wextra -shared
CFLAGS += -DFIELD_ELEMENTS_PER_BLOB=$(FIELD_ELEMENTS_PER_BLOB)
CFLAGS += ${addprefix -I,${INCLUDE_DIRS}}

.PHONY: all
all: blst ckzg ckzg-dotnet

.PHONY: blst
blst:
	cd ../../blst && $(BLST_BUILDSCRIPT)

.PHONY: ckzg
ckzg: blst
	$(CLANG_EXECUTABLE) $(CFLAGS) -o $(CKZG_LIBRARY_PATH) $(TARGETS)

.PHONY: ckzg-dotnet
ckzg-dotnet: ckzg
	dotnet build
	dotnet test
