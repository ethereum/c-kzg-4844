/*
 * This file contains fuzzing tests for C-KZG-4844.
 */
#include "../../src/c_kzg_4844.c"

///////////////////////////////////////////////////////////////////////////////
// Globals
///////////////////////////////////////////////////////////////////////////////

KZGSettings s;
bool initialized = false;

///////////////////////////////////////////////////////////////////////////////
// Trusted setup configuration
///////////////////////////////////////////////////////////////////////////////

static void setup(void) {
    FILE *fp;
    C_KZG_RET ret;

    /* Open the mainnet trusted setup file */
    fp = fopen("../src/trusted_setup.txt", "r");
    assert(fp != NULL);

    /* Load that trusted setup file */
    ret = load_trusted_setup_file(&s, fp);
    assert(ret == C_KZG_OK);

    fclose(fp);
}

///////////////////////////////////////////////////////////////////////////////
// Fuzzing functions
///////////////////////////////////////////////////////////////////////////////

#define INPUT_SIZE (       \
    BYTES_PER_BLOB +       \
    BYTES_PER_COMMITMENT + \
    BYTES_PER_PROOF)

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!initialized) {
        setup();
        initialized = true;
    }

    int offset = 0;
    size_t count = size / INPUT_SIZE;
    const Blob *blobs_bytes = (Blob *)(data + offset);
    offset += count * BYTES_PER_BLOB;
    const Bytes48 *commitments_bytes = (Bytes48 *)(data + offset);
    offset += count * BYTES_PER_COMMITMENT;
    const Bytes48 *proofs_bytes = (Bytes48 *)(data + offset);
    offset += count * BYTES_PER_PROOF;

    bool ok;
    verify_blob_kzg_proof_batch(
        &ok,
        blobs_bytes,
        commitments_bytes,
        proofs_bytes,
        count,
        &s
    );

    return 0;
}
