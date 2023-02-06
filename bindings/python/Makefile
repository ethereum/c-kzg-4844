INCLUDE_DIRS = .. ../../src ../../inc
INCLUDE_PY = $(shell python3 -c 'import sysconfig; print(sysconfig.get_config_var("INCLUDEPY"))')

FIELD_ELEMENTS_PER_BLOB?=4096

.PHONY: all
all: install test ecc_test

.PHONY: test
install: setup.py ckzg.c
	python3 setup.py install

.PHONY: test
test: tests.py
	python3 $<

.PHONY: ecc_test
ecc_test: py_ecc_tests.py
	python3 $<
