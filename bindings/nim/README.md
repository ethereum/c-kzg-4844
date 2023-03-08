# Nim bindings

This directory contains Nim bindings for the c-kzg-4844 library.

## Requirements

This bindings support Nim compiler version 1.2, 1.4, 1.6, and devel.

You also need to install dependencies:

```
nimble install stew
```

## Tests

Currently tests only support Nim compiler version 1.4, and 1.6 because of yaml library limitations.

Dependencies:

```
nimble install unittest2
nimble install yaml
```

Run the tests from folder `bindings\nim`:

```
nim test
```

## How to use this bindings in your project

Because the structure of folders is not a normal Nim library, we suggest you to
clone this repository in your project sub folder or submodule it.

Then you can import one of the binding file into your project.

## Library

The library which uses this binding is [nim-kzg4844](https://github.com/status-im/nim-kzg4844).
