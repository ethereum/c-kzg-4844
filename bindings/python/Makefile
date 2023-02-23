.PHONY: all
all: install test ecc_test

../../src/c-kzg-4844.o:
	cd ../../src/ && make blst && make

.PHONY: install
install: setup.py ckzg.c ../../src/c-kzg-4844.o
	python3 setup.py install

.PHONY: test
test: tests.py
	python3 $<

.PHONY: ecc_test
ecc_test: py_ecc_tests.py
	python3 $<
