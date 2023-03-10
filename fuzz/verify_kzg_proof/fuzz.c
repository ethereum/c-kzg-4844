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

#define INPUT_SIZE (48 + 32 + 32 + 48)

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!initialized) {
        setup();
        initialized = true;
    }

    if (size == INPUT_SIZE) {
        const Bytes48 *commitment_bytes = (Bytes48 *)(data);
        const Bytes32 *z_bytes = (Bytes32 *)(data + 48);
        const Bytes32 *y_bytes = (Bytes32 *)(data + 48 + 32);
        const Bytes48 *proof_bytes = (Bytes48 *)(data + 48 + 32 + 32);

        bool ok;
        verify_kzg_proof(
            &ok,
            commitment_bytes,
            z_bytes,
            y_bytes,
            proof_bytes,
            &s
        );
    }

    return 0;
}
