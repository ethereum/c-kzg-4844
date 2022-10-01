INCLUDE_DIRS = .. ../../min-src ../../inc

test: tests.cs libckzg.so ckzg.cs
	mcs -langversion:5 -optimize+ tests.cs ckzg.cs -r:System.Numerics.dll
	mono tests.exe

libckzg.so: c_kzg_4844_wrap.c ../../min-src/c_kzg_4844.o ../../lib/libblst.a
	clang -O -Wall -shared -fPIC -Wl,-Bsymbolic -I${INCLUDE_PY} ${addprefix -I,${INCLUDE_DIRS}} -o $@ $^

c_kzg_4844_wrap.c ckzg.cs: ../c_kzg_4844.swg
	swig -DSWIGWORDSIZE64 -O -Wall -csharp -outcurrentdir -namespace ckzg -outfile ckzg.cs $<
