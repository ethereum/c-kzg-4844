import { randomBytes } from "crypto";
import {
  loadTrustedSetup,
  freeTrustedSetup,
  blobToKzgCommitment,
  computeAggregateKzgProof,
  verifyAggregateKzgProof,
  BYTES_PER_FIELD,
  FIELD_ELEMENTS_PER_BLOB,
} from "./kzg";

const SETUP_FILE_PATH = "../../src/trusted_setup.txt";
const BLOB_BYTE_COUNT = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD;

const generateRandomBlob = () => new Uint8Array(randomBytes(BLOB_BYTE_COUNT));

describe("C-KZG", () => {
  beforeAll(() => {
    loadTrustedSetup(SETUP_FILE_PATH);
  });

  afterAll(() => {
    freeTrustedSetup();
  });

  it("computes the correct commitments and aggregate proofs from blobs", () => {
    const blobs = new Array(2).fill(0).map(generateRandomBlob);
    const commitments = blobs.map(blobToKzgCommitment);
    const proof = computeAggregateKzgProof(blobs);
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
});
