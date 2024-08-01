.PHONY: all
all: install test

.PHONY: install
install: $(CURDIR)/../../setup.py $(CURDIR)/ckzg_wrap.c
	python3 -m build --skip-dependency-check --outdir $(CURDIR)/dist $(CURDIR)/../../
	python3 -m pip install $(CURDIR)/dist/*.whl --force-reinstall

.PHONY: test
test: $(CURDIR)/tests.py
	python3 $<