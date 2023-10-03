#include "../base_fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    initialize();
    size_t blob_offset = 0;
    size_t commitment_offset = s.bytes_per_blob;
    size_t input_size = commitment_offset + BYTES_PER_COMMITMENT;

    if (size == input_size) {
        KZGProof proof;
        compute_blob_kzg_proof(
            &proof,
            (const uint8_t *)(data + blob_offset),
            (const Bytes48 *)(data + commitment_offset),
            &s
        );
    }
    return 0;
}
