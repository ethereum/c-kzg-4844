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
