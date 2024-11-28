# Node.js Bindings for the C-KZG Library

This directory contains Node.js bindings for the C-KZG-4844 library.

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
 * Initialize the library with a trusted setup file.
 *
 * Can pass either a .txt or a .json file with setup configuration. Converts
 * JSON formatted trusted setup into the native format that the base library
 * requires. The created file will be in the same as the origin file but with a
 * ".txt" extension.
 *
 * Uses user provided location first. If one is not provided then defaults to
 * the official Ethereum mainnet setup from the KZG ceremony. Should only be
 * used for cases where the Ethereum official mainnet KZG setup is acceptable.
 *
 * @param {string | undefined} filePath - .txt/.json file with setup configuration
 * @default - If no string is passed the default trusted setup from the Ethereum KZG ceremony is used
 *
 * @throws {TypeError} - Non-String input
 * @throws {Error} - For all other errors. See error message for more info
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
 * Verify a KZG proof claiming that `p(z) == y`.
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

### `computeCellsAndKzgProofs`

```ts
/**
 * Get the cells and proofs for a given blob.
 *
 * @param {Blob}    blob - the blob to get cells/proofs for
 *
 * @return {[Cell[], KZGProof[]]} - A tuple of cells and proofs
 *
 * @throws {Error} - Failure to allocate or compute cells and proofs
 */
export function computeCellsAndKzgProofs(blob: Blob): [Cell[], KZGProof[]];
```

### `recoverCellsAndKzgProofs`

```ts
/**
 * Given at least 50% of cells/proofs, reconstruct the missing ones.
 *
 * @param[in] {number[]}  cellIndices - The identifiers for the cells you have
 * @param[in] {Cell[]}    cells - The cells you have
 *
 * @return {[Cell[], KZGProof[]]} - A tuple of cells and proofs
 *
 * @throws {Error} - Invalid input, failure to allocate or error recovering
 * cells and proofs
 */
export function recoverCellsAndKzgProofs(
  cellIndices: number[],
  cells: Cell[],
): [Cell[], KZGProof[]];
```

### `verifyCellKzgProofBatch`

```ts
/**
 * Verify that multiple cells' proofs are valid.
 *
 * @param {Bytes48[]} commitmentsBytes - The commitments for each cell
 * @param {number[]}  cellIndices - The cell indices
 * @param {Cell[]}    cells - The cells to verify
 * @param {Bytes48[]} proofsBytes - The proof for each cell
 *
 * @return {boolean} - True if the cells are valid with respect to the given commitments
 *
 * @throws {Error} - Invalid input, failure to allocate memory, or errors verifying batch
 */
export function verifyCellKzgProofBatch(
  commitmentsBytes: Bytes48[],
  cellIndices: number[],
  cells: Cell[],
  proofsBytes: Bytes48[]
): boolean;
```
