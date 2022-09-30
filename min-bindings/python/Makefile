INCLUDE_DIRS = .. ../../min-src ../../inc
INCLUDE_PY = $(shell python -c 'import sysconfig; print(sysconfig.get_config_var("INCLUDEPY"))')

test: tests.py _ckzg.so
	python $<

_ckzg.so: c_kzg_4844_wrap.c ../../min-src/c_kzg_4844.o ../../lib/libblst.a
	clang -O -Wall -shared -fPIC -Wl,-Bsymbolic -I${INCLUDE_PY} ${addprefix -I,${INCLUDE_DIRS}} -o $@ $^

c_kzg_4844_wrap.c ckzg.py: ../c_kzg_4844.swg
	swig -DSWIGWORDSIZE64 -O -Wall -python -outcurrentdir $<
