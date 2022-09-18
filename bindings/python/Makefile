INCLUDE_DIRS = .. ../../src ../../inc
INCLUDE_PY = $(shell python -c 'import sysconfig; print(sysconfig.get_config_var("INCLUDEPY"))')

_ckzg.so: c_kzg_wrap.c ../../src/libckzg.a ../../lib/libblst.a
	clang -O -Wall -shared -fPIC -Wl,-Bsymbolic -I${INCLUDE_PY} ${addprefix -I,${INCLUDE_DIRS}} -o $@ $^

c_kzg_wrap.c ckzg.py: ../c_kzg.swg
	swig -O -python -outcurrentdir $<
