#include "../base_fuzz.h"

static const size_t COMMITMENT_OFFSET = 0;
static const size_t Z_OFFSET = COMMITMENT_OFFSET + BYTES_PER_COMMITMENT;
static const size_t Y_OFFSET = Z_OFFSET + BYTES_PER_FIELD_ELEMENT;
static const size_t PROOF_OFFSET = Y_OFFSET + BYTES_PER_FIELD_ELEMENT;
static const size_t INPUT_SIZE = PROOF_OFFSET + BYTES_PER_PROOF;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    initialize();
    if (size == INPUT_SIZE) {
        bool ok;
        verify_kzg_proof(
            &ok,
            (const Bytes48 *)(data + COMMITMENT_OFFSET),
            (const Bytes32 *)(data + Z_OFFSET),
            (const Bytes32 *)(data + Y_OFFSET),
            (const Bytes48 *)(data + PROOF_OFFSET),
            &s
        );
    }
    return 0;
}
