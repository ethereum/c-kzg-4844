import {existsSync} from "fs";
import {resolve} from "path";
const setupFileName = "testing_trusted_setups.json";

const SETUP_FILE_PATH = existsSync(setupFileName) ? setupFileName : `../../src/${setupFileName}`;

const MAX_TOP_BYTE = 114;

const TEST_DIR = "../../tests";
const BLOB_TO_KZG_COMMITMENT_TESTS = resolve(TEST_DIR, "blob_to_kzg_commitment");
const COMPUTE_KZG_PROOF_TESTS = resolve(TEST_DIR, "compute_kzg_proof");
const COMPUTE_BLOB_KZG_PROOF_TESTS = resolve(TEST_DIR, "compute_blob_kzg_proof");
const VERIFY_KZG_PROOF_TESTS = resolve(TEST_DIR, "verify_kzg_proof");
const VERIFY_BLOB_KZG_PROOF_TESTS = resolve(TEST_DIR, "verify_blob_kzg_proof");
const VERIFY_BLOB_KZG_PROOF_BATCH_TESTS = resolve(TEST_DIR, "verify_blob_kzg_proof_batch");
