import { randomBytes } from "crypto";
import {
  loadTrustedSetup,
  freeTrustedSetup,
  verifyKzgProof,
  blobToKzgCommitment,
  Blob,
  BLOB_SIZE,
  NUMBER_OF_FIELDS,
  computeAggregateKzgProof,
  verifyAggregateKzgProof,
} from "./kzg";

const SETUP_FILE_PATH = "../../src/trusted_setup.txt";

function generateRandomBlob(): Blob {
  return new Uint8Array(randomBytes(BLOB_SIZE * NUMBER_OF_FIELDS));
}

describe("C-KZG", () => {
  beforeEach(() => {
    loadTrustedSetup(SETUP_FILE_PATH);
  });

  afterEach(() => {
    freeTrustedSetup();
  });

  it("computes and verifies an aggregate KZG proof", async () => {
    const blob1 = generateRandomBlob();
    const blob2 = generateRandomBlob();
    const blobs = [blob1, blob2];

    const commitments = blobs.map(blobToKzgCommitment);

    const proof = computeAggregateKzgProof(blobs);

    console.log({
      commitments,
      proof,
    });

    const result = verifyAggregateKzgProof(blobs, commitments, proof);

    expect(result).toBe(true);
  });
});
