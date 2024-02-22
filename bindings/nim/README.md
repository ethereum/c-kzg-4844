# Nim bindings

This directory contains Nim bindings for the c-kzg-4844 library.

## Requirements

These bindings support Nim compiler version 1.2, 1.4, 1.6, and devel.

You also need to install dependencies:

```
nimble install stew
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

## How to use these bindings in your project

Install via nimble:

```
nimble install https://github.com/ethereum/c-kzg-4844
```

Then import one of `kzg4844/kzg`, `kzg4844/kzg_abi`, or `kzg4844/kzg_ex` into your project.
