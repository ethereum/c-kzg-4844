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

#define INPUT_SIZE (BYTES_PER_BLOB + BYTES_PER_FIELD_ELEMENT)

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!initialized) {
        setup();
        initialized = true;
    }

    if (size == INPUT_SIZE) {
        const Blob *blob_bytes = (Blob *)(data);
        const Bytes32 *z_bytes = (Bytes32 *)(data + BYTES_PER_BLOB);

        KZGProof proof;
        Bytes32 y;
        compute_kzg_proof(
            &proof,
            &y,
            blob_bytes,
            z_bytes,
            &s
        );
    }

    return 0;
}
