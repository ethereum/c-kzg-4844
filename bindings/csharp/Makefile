INCLUDE_DIRS = ../../src ../../blst/bindings

ifeq ($(OS),Windows_NT)
	BLST_BUILDSCRIPT=./build.sh
	BLST_OBJ=libblst.a
	TESTS_EXECUTABLE=test_ckzg.exe
	CSHARP_PLATFORM?=win-x64
	CLANG_PLATFROM?=x86_64-win
	CLANG_FLAGS=
	CLANG_EXECUTABLE=gcc
	CKZG_LIBRARY_PATH=Ckzg\runtimes\$(CSHARP_PLATFORM)\native\ckzg.dll
else
	BLST_BUILDSCRIPT=./build.sh
	BLST_OBJ=libblst.a
	TESTS_EXECUTABLE=./test_ckzg
	CSHARP_PLATFORM?=linux-x64
	CLANG_PLATFORM?=x86_64-linux
	CLANG_FLAGS=-fPIC
	CLANG_EXECUTABLE=cc
	CKZG_LIBRARY_PATH=Ckzg/runtimes/$(CSHARP_PLATFORM)/native/ckzg.so
endif

.blst:
	cd ../../blst &&\
	git apply ../blst_sha.patch &&\
	$(BLST_BUILDSCRIPT) &&\
	uname -a && ls -a &&\
	git apply -R ../blst_sha.patch &&\
	cd ../bindings/csharp

.ckzg: ckzg.c ../../src/c_kzg_4844.c ../../blst/$(BLST_OBJ)
	$(CLANG_EXECUTABLE) -O -Wall -shared $(CLANG_FLAGS) ${addprefix -I,${INCLUDE_DIRS}} -o $(CKZG_LIBRARY_PATH) $^

# Ckzg library
ckzg:
	@make .blst
	@make .ckzg

# E2e tests as an executable
test: tests.c ckzg.c ../../src/c_kzg_4844.c ../../blst/$(BLST_OBJ)
	@make .blst
	clang -O -w -Wall $(CLANG_FLAGS) ${addprefix -I,${INCLUDE_DIRS}} -o $(TESTS_EXECUTABLE) $^ 

# E2e tests are built and run
run-test:
	@make test
	$(TESTS_EXECUTABLE)

# Makes a build and a nuget package just for windows or linux
# To build full package - use ckzg command on every plaform and dotnet build
ckzg-dotnet:
	@make ckzg
	dotnet build