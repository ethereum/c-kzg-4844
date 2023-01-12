INCLUDE_DIRS = .. ../../src ../../inc
INCLUDE_PY = $(shell python3 -c 'import sysconfig; print(sysconfig.get_config_var("INCLUDEPY"))')

FIELD_ELEMENTS_PER_BLOB?=4096

.PHONY: all

all: test ecc_test

test: tests.py ckzg.so
	python3 $<

ecc_test: py_ecc_tests.py ckzg.so
	python3 $<

ckzg.so: ckzg.c ../../src/c_kzg_4844.o ../../lib/libblst.a
	clang -O -Wall -shared -fPIC -Wl,-Bsymbolic -I${INCLUDE_PY} ${addprefix -I,${INCLUDE_DIRS}} -DFIELD_ELEMENTS_PER_BLOB=${FIELD_ELEMENTS_PER_BLOB} -o $@ $^
