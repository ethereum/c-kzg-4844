import { randomBytes } from "crypto";
import { existsSync } from "fs";

import {
  loadTrustedSetup,
  freeTrustedSetup,
  blobToKzgCommitment,
  computeAggregateKzgProof,
  verifyAggregateKzgProof,
  BYTES_PER_FIELD_ELEMENT,
  FIELD_ELEMENTS_PER_BLOB,
} from "./kzg";

const setupFileName = "trusted_setup.txt";

const SETUP_FILE_PATH = existsSync(setupFileName)
  ? setupFileName
  : `../../src/${setupFileName}`;

const BLOB_BYTE_COUNT = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

const generateRandomBlob = () => new Uint8Array(randomBytes(BLOB_BYTE_COUNT));

describe("C-KZG", () => {
  beforeAll(() => {
    loadTrustedSetup(SETUP_FILE_PATH);
  });

  afterAll(() => {
    freeTrustedSetup();
  });

  it("computes the correct commitments and aggregate proof from blobs", () => {
    let blobs = new Array(2).fill(0).map(generateRandomBlob);
    let commitments = blobs.map(blobToKzgCommitment);
    let proof = computeAggregateKzgProof(blobs);
    expect(verifyAggregateKzgProof(blobs, commitments, proof)).toBe(true);
  });

  it("computes the aggregate proof when blobs is an empty array", () => {
    const proof = computeAggregateKzgProof([]);

    // Is this actually what the aggregate proof for an empty array should be?
    expect(proof.toString()).toEqual(
      [
        192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,
      ].toString(),
    );
  });

  it("fails when given incorrect commitments", () => {
    const blobs = new Array(2).fill(0).map(generateRandomBlob);
    const commitments = blobs.map(blobToKzgCommitment);
    commitments[0][0] = commitments[0][0] === 0 ? 1 : 0; // Mutate the commitment
    const proof = computeAggregateKzgProof(blobs);
    expect(() =>
      verifyAggregateKzgProof(blobs, commitments, proof),
    ).toThrowError("Invalid commitment data");
  });
});
