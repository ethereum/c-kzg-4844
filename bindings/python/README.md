# Python Bindings for the C-KZG Library

This directory contains Python bindings for the C-KZG-4844 library.

## Prerequisites

These bindings require `python3`, `PyYAML` and `make`.
```
sudo apt install python3 python3-pip
python3 -m pip install build PyYAML
```

## Build & test

Everything is consolidated into one command:
```
make
```

You should expect to see these messages at the bottom:
```
python3 tests.py
tests passed
```