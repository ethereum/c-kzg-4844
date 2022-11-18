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
  transformTrustedSetupJSON,
} from "./kzg";

const setupFileName = "testing_trusted_setups.json";

const SETUP_FILE_PATH = existsSync(setupFileName)
  ? setupFileName
  : `../../src/${setupFileName}`;

const BLOB_BYTE_COUNT = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;

const generateRandomBlob = () => new Uint8Array(randomBytes(BLOB_BYTE_COUNT));

describe("C-KZG", () => {
  beforeAll(async () => {
    const file = await transformTrustedSetupJSON(SETUP_FILE_PATH);
    loadTrustedSetup(file);
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

  // Just don't call verifyAggregateKzgProof when there are no blobs or commitments
  it.skip("verifies the aggregate proof of empty blobs and commitments", () => {
    expect(verifyAggregateKzgProof([], [], computeAggregateKzgProof([]))).toBe(
      true,
    );
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
    ).toThrowError("Invalid commitment data");
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
