INCLUDE_DIRS = ../../src ../../blst/bindings
CLANG_EXECUTABLE=clang
FIELD_ELEMENTS_PER_BLOB?=4096
ifdef ARCH
	TARGET=--target=$(ARCH)
endif
CLANG_FLAGS+= -DFIELD_ELEMENTS_PER_BLOB=$(FIELD_ELEMENTS_PER_BLOB) -O2 -fno-builtin -Wall -Wextra $(TARGET) -mno-avx
TARGETS=ckzg.c ../../src/c_kzg_4844.c ../../blst/$(BLST_OBJ)

ifeq ($(OS),Windows_NT)
	BLST_BUILDSCRIPT=./build.bat
	BLST_OBJ=blst.lib
	TESTS_EXECUTABLE=test_ckzg.exe
	LOCATION?=win-x64
	CKZG_LIBRARY_PATH=Ckzg.Bindings\runtimes\$(LOCATION)\native\ckzg$(EXTENSION)
else
	BLST_BUILDSCRIPT=./build.sh
	BLST_OBJ=libblst.a
	TESTS_EXECUTABLE=./test_ckzg
	LOCATION?=linux-x64
	CLANG_FLAGS+= -fPIC
	CKZG_LIBRARY_PATH=Ckzg.Bindings/runtimes/$(LOCATION)/native/ckzg$(EXTENSION)
endif

.blst:
	cd ../../blst &&\
	git apply ../blst_sha.patch &&\
	CC=$(CLANG_EXECUTABLE) CFLAGS="$(CLANG_FLAGS)" $(BLST_BUILDSCRIPT) ||\
	git apply -R ../blst_sha.patch &&\
	cd ../bindings/csharp

.ckzg: 
	$(CLANG_EXECUTABLE) $(CLANG_FLAGS) -shared ${addprefix -I,${INCLUDE_DIRS}} -o $(CKZG_LIBRARY_PATH) $(TARGETS)

# Ckzg library
ckzg:
	@make .blst
	@make .ckzg

# E2e tests as an executable
test:
	@make .blst
	$(CLANG_EXECUTABLE) $(CLANG_FLAGS) ${addprefix -I,${INCLUDE_DIRS}} -o $(TESTS_EXECUTABLE) kzg_tests.c $(TARGETS)

# E2e tests are built and run
run-test:
	@make test
	$(TESTS_EXECUTABLE)

# Makes a build and a nuget package just for windows or linux
# To build full package - use ckzg command on every plaform and dotnet build
ckzg-dotnet:
	@make ckzg
	dotnet build