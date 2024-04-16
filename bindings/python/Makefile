.PHONY: all
all: install test

.PHONY: install
install: ../../setup.py ckzg.c
	python3 ../../setup.py install --force

.PHONY: test
test: tests.py
	python3 $<
