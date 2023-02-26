import path from "path";
// import {existsSync} from "fs";
import {resolve} from "path";

export const MAX_TOP_BYTE = 114;
export const SETUP_FILE_NAME = "testing_trusted_setups.json";
export const TRUSTED_SETUP_JSON = path.resolve(__dirname, "__fixtures__", SETUP_FILE_NAME);

// const SETUP_FILE_PATH = existsSync(setupFileName) ? setupFileName : `../../src/${setupFileName}`;

const TEST_DIR = "../../tests";
export const BLOB_TO_KZG_COMMITMENT_TESTS = resolve(TEST_DIR, "blob_to_kzg_commitment");
export const COMPUTE_KZG_PROOF_TESTS = resolve(TEST_DIR, "compute_kzg_proof");
export const COMPUTE_BLOB_KZG_PROOF_TESTS = resolve(TEST_DIR, "compute_blob_kzg_proof");
export const VERIFY_KZG_PROOF_TESTS = resolve(TEST_DIR, "verify_kzg_proof");
export const VERIFY_BLOB_KZG_PROOF_TESTS = resolve(TEST_DIR, "verify_blob_kzg_proof");
export const VERIFY_BLOB_KZG_PROOF_BATCH_TESTS = resolve(TEST_DIR, "verify_blob_kzg_proof_batch");
