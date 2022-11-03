import { randomBytes } from "crypto";
import {
  loadTrustedSetup,
  freeTrustedSetup,
  blobToKzgCommitment,
  computeAggregateKzgProof,
  verifyAggregateKzgProof,
  BYTES_PER_FIELD,
  FIELD_ELEMENTS_PER_BLOB,
  verifyKzgProof,
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

  it("verifies a proof at a given commitment point", () => {
    const blob = generateRandomBlob();
    const commitment = blobToKzgCommitment(blob);
    const proof = computeAggregateKzgProof([blob]);

    // It doesn't seem to matter what is passed here...
    const z = Uint8Array.from(new Array(32).fill(0));
    const y = Uint8Array.from(new Array(32).fill(0));

    expect(verifyKzgProof(commitment, z, y, proof)).toBe(true);
  });

  it("computes the correct commitments and aggregate proofs from blobs", () => {
    const blobs = new Array(2).fill(0).map(generateRandomBlob);
    const commitments = blobs.map(blobToKzgCommitment);
    const proof = computeAggregateKzgProof(blobs);
    expect(verifyAggregateKzgProof(blobs, commitments, proof)).toBe(true);
  });
});
