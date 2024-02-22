# C-KZG-4844

This is a TypeScript library for EIP-4844 that implements the [Polynomial
Commitments](https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md)
API. The core functionality was originally a stripped-down copy of
[C-KZG](https://github.com/benjaminion/c-kzg), but has been heavily modified
since then. This package wraps that native `c-kzg` C code in C/C++ NAPI
bindings for use in node.js applications.

Spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md

## Prerequisites

Installation requires compilation of C code. Target environment must have:

- A compiler like g++ or clang
- [`make`](https://www.gnu.org/software/make/manual/make.html)
- [`python3`](https://docs.python.org/3/)

## Installation

```sh
yarn add c-kzg
# or
npm i -S c-kzg
```

## Usage

```ts
import {
  BYTES_PER_BLOB,
  Blob,
  Bytes48,
  blobToKzgCommitment,
  computeBlobKzgProof,
  verifyBlobKzgProofBatch,
} from "c-kzg";

const blobs = [] as Blob[];
const commitments = [] as Bytes48[];
const proofs = [] as Bytes48[];

for (let i = 0; i < BATCH_SIZE; i++) {
  blobs.push(Buffer.alloc(BYTES_PER_BLOB, "*"));
  commitments.push(blobToKzgCommitment(blobs[i]));
  proofs.push(computeBlobKzgProof(blobs[i], commitments[i]));
}

const isValid = verifyBlobKzgProofBatch(blobs, commitments, proofs);
```

## API

### `loadTrustedSetup`

```ts
/**
 * Sets up the c-kzg library. Pass in a properly formatted trusted setup file
 * to configure the library.  File must be in json format, see TrustedSetupJson
 * interface for more details, or as a properly formatted utf-8 encoded file.
 *
 * @remark This function must be run before any other functions in this
 *         library can be run.
 *
 * @param {string} filePath - The absolute path of the trusted setup
 */
loadTrustedSetup(filePath: string): void;
```

### `blobToKzgCommitment`

```ts
/**
 * Convert a blob to a KZG commitment.
 *
 * @param {Blob} blob - The blob representing the polynomial to be committed to
 */
blobToKzgCommitment(blob: Blob): KZGCommitment;
```

### `computeKzgProof`

```ts
/**
 * Compute KZG proof for polynomial in Lagrange form at position z.
 *
 * @param {Blob}    blob - The blob (polynomial) to generate a proof for
 * @param {Bytes32} zBytes - The generator z-value for the evaluation points
 *
 * @return {ProofResult} - Tuple containing the resulting proof and evaluation
 *                         of the polynomial at the evaluation point z
 */
computeKzgProof(blob: Blob, zBytes: Bytes32): ProofResult;
```

### `computeBlobKzgProof`

```ts
/**
 * Given a blob, return the KZG proof that is used to verify it against the
 * commitment.
 *
 * @param {Blob}    blob - The blob (polynomial) to generate a proof for
 * @param {Bytes48} commitmentBytes - Commitment to verify
 */
computeBlobKzgProof(
  blob: Blob,
  commitmentBytes: Bytes48,
): KZGProof;
```

### `verifyKzgProof`

```ts
/**
 * Verify a KZG poof claiming that `p(z) == y`.
 *
 * @param {Bytes48} commitmentBytes - The serialized commitment corresponding to
 *                                    polynomial p(x)
 * @param {Bytes32} zBytes - The serialized evaluation point
 * @param {Bytes32} yBytes - The serialized claimed evaluation result
 * @param {Bytes48} proofBytes - The serialized KZG proof
 */
verifyKzgProof(
  commitmentBytes: Bytes48,
  zBytes: Bytes32,
  yBytes: Bytes32,
  proofBytes: Bytes48,
): boolean;
```

### `verifyBlobKzgProof`

```ts
/**
 * Given a blob and its proof, verify that it corresponds to the provided
 * commitment.
 *
 * @param {Blob}    blob - The serialized blob to verify
 * @param {Bytes48} commitmentBytes - The serialized commitment to verify
 * @param {Bytes48} proofBytes - The serialized KZG proof for verification
 */
verifyBlobKzgProof(
  blob: Blob,
  commitmentBytes: Bytes48,
  proofBytes: Bytes48,
): boolean;
```

### `verifyBlobKzgProofBatch`

```ts
/**
 * Given an array of blobs and their proofs, verify that they correspond to
 * their provided commitment.
 *
 * Note: blobs[0] relates to commitmentBytes[0] and proofBytes[0]
 *
 * @param {Blob}    blobs - An array of serialized blobs to verify
 * @param {Bytes48} commitmentBytes - An array of serialized commitments to
 *                                    verify
 * @param {Bytes48} proofBytes - An array of serialized KZG proofs for
 *                               verification
 */
verifyBlobKzgProofBatch(
  blobs: Blob[],
  commitmentsBytes: Bytes48[],
  proofsBytes: Bytes48[],
): boolean;
```
