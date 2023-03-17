.PHONY: all
all: install test ecc_test

../../src/c_kzg_4844.o:
	make -C../../src c_kzg_4844.o

.PHONY: install
install: setup.py ckzg.c ../../src/c_kzg_4844.o
	python3 setup.py install

.PHONY: test
test: tests.py
	python3 $<

.PHONY: ecc_test
ecc_test: py_ecc_tests.py
	python3 $<
