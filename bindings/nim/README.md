# Nim Bindings for the C-KZG Library

This directory contains Nim bindings for the C-KZG-4844 library.

## Prerequisites

These bindings support Nim compiler version 1.2, 1.4, 1.6, and devel.

You also need to install dependencies:

```
nimble install stew
```

## Installation

Install via nimble:

```
nimble install https://github.com/ethereum/c-kzg-4844
```

## Tests

Currently, reference tests only support Nim compiler version 1.4, and 1.6 because of yaml library limitations.
But other tests that are not using yaml can be run by Nim 1.2 - devel.

Dependencies:

```
nimble install unittest2
nimble install yaml
```

Run the tests from folder `bindings\nim`:

```
nim test
```

Or from c-kzg-4844 root folder:

```
nimble test
```

## Usage

After installation, import `kzg4844/kzg` or `kzg4844/kzg_abi` into your project.
