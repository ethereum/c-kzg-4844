This package wraps the c-kzg C code in C++ NAPI bindings which allow it to be imported into a NodeJS program.

Spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md

# Usage

Install this library with

```sh
yarn add c-kzg
```

Import from it like any other library

```js
import {
  KZGCommitment,
  blobToKzgCommitment,
  verifyAggregateKzgProof,
  loadTrustedSetup,
  transformTrustedSetupJSON,
} from "c-kzg";
```

# Requirements

The C and C++ code is compiled by node-gyp on installation. Your environment will need

- A compiler like g++ or clang
- `make`
- `python3`

# Contributing

This directory contains the code necessary to generate NodeJS bindings for C-KZG.

The bindings file has the following interface:

```js

  loadTrustedSetup: (filePath: string) => SetupHandle;

  freeTrustedSetup: (setupHandle: SetupHandle) => void;

  blobToKzgCommitment: (blob: Blob, setupHandle: SetupHandle) => KZGCommitment;

  computeAggregateKzgProof: (
    blobs: Blob[],
    setupHandle: SetupHandle
  ) => KZGProof;

  verifyAggregateKzgProof: (
    blobs: Blob[],
    expectedKzgCommitments: KZGCommitment[],
    kzgAggregatedProof: KZGProof,
    setupHandle: SetupHandle
  ) => boolean;
```

But this library wraps it in module with manages the setupHandle internally.

First,
`npm install -g yarn` if you don't have it.

Install the blst submodule

```sh
git submodule update --init
```

Build blst and c_kzg_4844.c

```
cd src && make blst lib
```

Generate NodeJS bindings and run the TypeScript tests against them

```sh
cd ../bindings/node.js && yarn install && make test
```

After doing this once, you can re-build (if necessary) and re-run the tests with

```sh
make build test
```

After making changes, regenerate the distributable JS and type defs

```sh
make bundle
```
