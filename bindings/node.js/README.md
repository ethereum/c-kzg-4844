# C-KZG-4844

This is a TypeScript library for EIP-4844 and EIP-7594 that implements the
[Polynomial Commitments](https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md)
API. The core functionality was originally a stripped-down copy of
[C-KZG](https://github.com/benjaminion/c-kzg), but has been heavily modified
since then. This package wraps that native `c-kzg` C code in C/C++ NAPI
bindings for use in node.js applications.

Important Links:
[EIP-4844 - Polynomial Commitments](https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md)
[EIP-7594 - Polynomial Commitments Sampling](https://github.com/ethereum/consensus-specs/blob/dev/specs/_features/eip7594/polynomial-commitments-sampling.md)

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
  blobToKZGCommitment,
  computeBlobKZGProof,
  verifyBlobKZGProofBatch,
} from "c-kzg";

const blobs = [] as Blob[];
const commitments = [] as Bytes48[];
const proofs = [] as Bytes48[];

for (let i = 0; i < BATCH_SIZE; i++) {
  blobs.push(Buffer.alloc(BYTES_PER_BLOB, "*"));
  commitments.push(blobToKZGCommitment(blobs[i]));
  proofs.push(computeBlobKZGProof(blobs[i], commitments[i]));
}

const isValid = verifyBlobKZGProofBatch(blobs, commitments, proofs);
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

### `blobToKZGCommitment`

```ts
/**
 * Convert a blob to a KZG commitment.
 *
 * @param {Blob} blob - The blob representing the polynomial to be committed to
 */
blobToKZGCommitment(blob: Blob): KZGCommitment;
```

### `computeKZGProof`

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
computeKZGProof(blob: Blob, zBytes: Bytes32): ProofResult;
```

### `computeBlobKZGProof`

```ts
/**
 * Given a blob, return the KZG proof that is used to verify it against the
 * commitment.
 *
 * @param {Blob}    blob - The blob (polynomial) to generate a proof for
 * @param {Bytes48} commitmentBytes - Commitment to verify
 */
computeBlobKZGProof(
  blob: Blob,
  commitmentBytes: Bytes48,
): KZGProof;
```

### `verifyKZGProof`

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
verifyKZGProof(
  commitmentBytes: Bytes48,
  zBytes: Bytes32,
  yBytes: Bytes32,
  proofBytes: Bytes48,
): boolean;
```

### `verifyBlobKZGProof`

```ts
/**
 * Given a blob and its proof, verify that it corresponds to the provided
 * commitment.
 *
 * @param {Blob}    blob - The serialized blob to verify
 * @param {Bytes48} commitmentBytes - The serialized commitment to verify
 * @param {Bytes48} proofBytes - The serialized KZG proof for verification
 */
verifyBlobKZGProof(
  blob: Blob,
  commitmentBytes: Bytes48,
  proofBytes: Bytes48,
): boolean;
```

### `verifyBlobKZGProofBatch`

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
verifyBlobKZGProofBatch(
  blobs: Blob[],
  commitmentsBytes: Bytes48[],
  proofsBytes: Bytes48[],
): boolean;
```

### `computeCellsAndKZGProofs`

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
export function computeCellsAndKZGProofs(blob: Blob): [Cell[], KZGProof[]];
```

### `recoverCellsAndKZGProofs`

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
export function recoverCellsAndKZGProofs(
  cellIndices: number[],
  cells: Cell[],
): [Cell[], KZGProof[]];
```

### `verifyCellKZGProofBatch`

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
export function verifyCellKZGProofBatch(
  commitmentsBytes: Bytes48[],
  cellIndices: number[],
  cells: Cell[],
  proofsBytes: Bytes48[]
): boolean;
```
