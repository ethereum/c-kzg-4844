INCLUDE_DIRS = .. ../../min-src ../../inc
INCLUDE_PY = $(shell python -c 'import sysconfig; print(sysconfig.get_config_var("INCLUDEPY"))')

.PHONY: all

all: test ecc_test

test: tests.py ckzg.so
	python $<

ecc_test: py_ecc_tests.py ckzg.so
	python $<

ckzg.so: ckzg.c ../../min-src/c_kzg_4844.o ../../lib/libblst.a
	clang -O -Wall -shared -fPIC -Wl,-Bsymbolic -I${INCLUDE_PY} ${addprefix -I,${INCLUDE_DIRS}} -o $@ $^
