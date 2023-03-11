#include "../base_fuzz.h"

static const size_t BLOB_OFFSET = 0;
static const size_t COMMITMENT_OFFSET = BLOB_OFFSET + BYTES_PER_BLOB;
static const size_t PROOF_OFFSET = COMMITMENT_OFFSET + BYTES_PER_COMMITMENT;
static const size_t INPUT_SIZE = PROOF_OFFSET + BYTES_PER_PROOF;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    initialize();
    if (size == INPUT_SIZE) {
        bool ok;
        verify_blob_kzg_proof(
            &ok,
            (const Blob *)(data + BLOB_OFFSET),
            (const Bytes48 *)(data + COMMITMENT_OFFSET),
            (const Bytes48 *)(data + PROOF_OFFSET),
            &s
        );
    }
    return 0;
}
