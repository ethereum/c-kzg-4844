INCLUDE_DIRS = .. ../../min-src ../../inc

test: tests.cs ckzg.dll
	mcs tests.cs -r:System.Numerics
	./tests.exe

ckzg.dll: ckzg.c ../../min-src/c_kzg_4844.o ../../lib/libblst.a
	clang -O -Wall -shared ${addprefix -I,${INCLUDE_DIRS}} -o $@ $^
