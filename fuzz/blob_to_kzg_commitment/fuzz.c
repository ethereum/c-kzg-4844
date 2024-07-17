#include "../base_fuzz.h"

static const size_t BLOB_OFFSET = 0;
static const size_t INPUT_SIZE = BLOB_OFFSET + BYTES_PER_BLOB;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    initialize();
    if (size == INPUT_SIZE) {
        KZGCommitment commitment;
        blob_to_kzg_commitment(
            &commitment,
            (const Blob *)(data + BLOB_OFFSET),
            &s
        );
    }
    return 0;
}
