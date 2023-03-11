#include "../base_fuzz.h"

static const size_t BLOB_OFFSET = 0;
static const size_t COMMITMENT_OFFSET = BYTES_PER_BLOB;
static const size_t INPUT_SIZE = COMMITMENT_OFFSET + BYTES_PER_COMMITMENT;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    initialize();
    if (size == INPUT_SIZE) {
        KZGProof proof;
        compute_blob_kzg_proof(
            &proof,
            (const Blob *)(data + BLOB_OFFSET),
            (const Bytes48 *)(data + COMMITMENT_OFFSET),
            &s
        );
    }
    return 0;
}
