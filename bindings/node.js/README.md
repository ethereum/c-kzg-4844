This directory contains the code necessary to generate NodeJS bindings for C-KZG.

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

Spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md

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
