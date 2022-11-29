INCLUDE_DIRS = ../../src ../../blst/bindings

FIELD_ELEMENTS_PER_BLOB ?= 4096

ifeq ($(OS),Windows_NT)
	BLST_BUILDSCRIPT=./build.bat
	BLST_OBJ=blst.lib
	TESTS_EXECUTABLE=test_ckzg.exe
	CSHARP_PLATFORM?=win-x64
	CLANG_PLATFROM?=x86_64-win
	CLANG_FLAGS=
	CLANG_EXECUTABLE=clang
	CKZG_LIBRARY_PATH=Ckzg.Bindings\runtimes\$(CSHARP_PLATFORM)\native\ckzg.dll
else
	BLST_BUILDSCRIPT=./build.sh
	BLST_OBJ=libblst.a
	TESTS_EXECUTABLE=./test_ckzg
	CSHARP_PLATFORM?=linux-x64
	CLANG_PLATFORM?=x86_64-linux
	CLANG_FLAGS=-fPIC
	CLANG_EXECUTABLE=cc
	CKZG_LIBRARY_PATH=Ckzg.Bindings/runtimes/$(CSHARP_PLATFORM)/native/ckzg.so
endif

CLANG_FLAGS += -DFIELD_ELEMENTS_PER_BLOB=$(FIELD_ELEMENTS_PER_BLOB)

TARGETS=ckzg.c ../../src/c_kzg_4844.c ../../blst/$(BLST_OBJ)

.blst:
	cd ../../blst &&\
	git apply ../blst_sha.patch &&\
	$(BLST_BUILDSCRIPT) &&\
	git apply -R ../blst_sha.patch &&\
	cd ../bindings/csharp

.ckzg:
	$(CLANG_EXECUTABLE) -O -Wall -shared $(CLANG_FLAGS) ${addprefix -I,${INCLUDE_DIRS}} -o $(CKZG_LIBRARY_PATH) $(TARGETS)

# Ckzg library
ckzg:
	@make .blst
	@make .ckzg

# E2e tests as an executable
test:
	@make .blst
	$(CLANG_EXECUTABLE) -O -w -Wall $(CLANG_FLAGS) ${addprefix -I,${INCLUDE_DIRS}} -o $(TESTS_EXECUTABLE) kzg_tests.c $(TARGETS)

# E2e tests are built and run
run-test:
	@make test
	$(TESTS_EXECUTABLE)

# Makes a build and a nuget package just for windows or linux
# To build full package - use ckzg command on every plaform and dotnet build
ckzg-dotnet:
	@make ckzg
	dotnet build
