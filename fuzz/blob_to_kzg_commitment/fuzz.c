#include "../base_fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    initialize();
    size_t blob_offset = 0;
    size_t input_size = blob_offset + s.bytes_per_blob;

    if (size == input_size) {
        KZGCommitment commitment;
        blob_to_kzg_commitment(
            &commitment,
            (const uint8_t *)(data + blob_offset),
            &s
        );
    }
    return 0;
}
