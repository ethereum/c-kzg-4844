#include "../base_fuzz.h"

static const size_t BLOB_OFFSET = 0;
static const size_t Z_OFFSET = BLOB_OFFSET + BYTES_PER_BLOB;
static const size_t INPUT_SIZE = Z_OFFSET + BYTES_PER_FIELD_ELEMENT;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    initialize();
    if (size == INPUT_SIZE) {
        KZGProof proof;
        Bytes32 y;
        compute_kzg_proof(
            &proof,
            &y,
            (const Blob *)(data + BLOB_OFFSET),
            (const Bytes32 *)(data + Z_OFFSET),
            &s
        );
    }
    return 0;
}
