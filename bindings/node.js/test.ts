import { randomBytes } from "crypto";
import { existsSync } from "fs";

import {
  loadTrustedSetup,
  freeTrustedSetup,
  blobToKzgCommitment,
  verifyKzgProof,
  computeKzgProof,
  computeAggregateKzgProof,
  verifyAggregateKzgProof,
  BYTES_PER_FIELD_ELEMENT,
  FIELD_ELEMENTS_PER_BLOB,
  transformTrustedSetupJSON,
} from "./kzg";

const setupFileName = "testing_trusted_setups.json";

const SETUP_FILE_PATH = existsSync(setupFileName)
  ? setupFileName
  : `../../src/${setupFileName}`;

const BLOB_BYTE_COUNT = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

const MAX_TOP_BYTE = 114;

const generateRandomBlob = () => {
  return new Uint8Array(
    randomBytes(BLOB_BYTE_COUNT).map((x, i) => {
      // Set the top byte to be low enough that the field element doesn't overflow the BLS modulus
      if (x > MAX_TOP_BYTE && i % BYTES_PER_FIELD_ELEMENT == 31) {
        return Math.floor(Math.random() * MAX_TOP_BYTE);
      }
      return x;
    }),
  );
};

describe("C-KZG", () => {
  beforeAll(async () => {
    const file = await transformTrustedSetupJSON(SETUP_FILE_PATH);
    loadTrustedSetup(file);
  });

  afterAll(() => {
    freeTrustedSetup();
  });

  it("computes a proof from blob", () => {
    let blob = generateRandomBlob();
    const zBytes = new Uint8Array(32).fill(0);
    computeKzgProof(blob, zBytes);
    // No check, just make sure it doesn't crash.
  });

  it("computes the correct commitments and aggregate proof from blobs", () => {
    let blobs = new Array(2).fill(0).map(generateRandomBlob);
    let commitments = blobs.map(blobToKzgCommitment);
    let proof = computeAggregateKzgProof(blobs);
    expect(verifyAggregateKzgProof(blobs, commitments, proof)).toBe(true);
  });

  it("returns the identity (aka zero, aka neutral) element when blobs is an empty array", () => {
    const aggregateProofOfNothing = computeAggregateKzgProof([]);
    expect(aggregateProofOfNothing.toString()).toEqual(
      [
        192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,
      ].toString(),
    );
  });

  it("verifies the aggregate proof of empty blobs and commitments", () => {
    expect(verifyAggregateKzgProof([], [], computeAggregateKzgProof([]))).toBe(
      true,
    );
  });

  it("verifies a valid KZG proof", () => {
    const commitment = new Uint8Array(48).fill(0);
    commitment[0] = 0xc0;
    const z = new Uint8Array(32).fill(0);
    const y = new Uint8Array(32).fill(0);
    const proof = new Uint8Array(48).fill(0);
    proof[0] = 0xc0;

    expect(verifyKzgProof(commitment, z, y, proof)).toBe(true);
  });

  it("verifies an invalid valid KZG proof", () => {
    const commitment = new Uint8Array(48).fill(0);
    commitment[0] = 0xc0;
    const z = new Uint8Array(32).fill(1);
    const y = new Uint8Array(32).fill(1);
    const proof = new Uint8Array(48).fill(0);
    proof[0] = 0xc0;

    expect(verifyKzgProof(commitment, z, y, proof)).toBe(false);
  });

  it("computes the aggregate proof when for a single blob", () => {
    let blobs = new Array(1).fill(0).map(generateRandomBlob);
    let commitments = blobs.map(blobToKzgCommitment);
    let proof = computeAggregateKzgProof(blobs);
    expect(verifyAggregateKzgProof(blobs, commitments, proof)).toBe(true);
  });

  it("fails when given incorrect commitments", () => {
    const blobs = new Array(2).fill(0).map(generateRandomBlob);
    const commitments = blobs.map(blobToKzgCommitment);
    commitments[0][0] = commitments[0][0] === 0 ? 1 : 0; // Mutate the commitment
    const proof = computeAggregateKzgProof(blobs);
    expect(() =>
      verifyAggregateKzgProof(blobs, commitments, proof),
    ).toThrowError("verify_aggregate_kzg_proof failed with error code: 1");
  });

  it("throws the expected error when given fewer commitments than blobs", () => {
    let blobs = new Array(1).fill(0).map(generateRandomBlob);
    let commitments = [] as Uint8Array[];
    let proof = computeAggregateKzgProof(blobs);
    expect(() =>
      verifyAggregateKzgProof(blobs, commitments, proof),
    ).toThrowError(
      "verifyAggregateKzgProof requires blobs count to match expectedKzgCommitments count",
    );
  });

  describe("computing commitment from blobs", () => {
    it("throws as expected when given an argument of invalid type", () => {
      // @ts-expect-error
      expect(() => blobToKzgCommitment("wrong type")).toThrowError(
        "Invalid argument type: blob. Expected UInt8Array",
      );
    });
  });
});
