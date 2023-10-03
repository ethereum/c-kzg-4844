#include "../base_fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    initialize();
    size_t blob_offset = 0;
    size_t commitment_offset = blob_offset + s.bytes_per_blob;
    size_t proof_offset = commitment_offset + BYTES_PER_COMMITMENT;
    size_t input_size = proof_offset + BYTES_PER_PROOF;

    if (size == input_size) {
        bool ok;
        verify_blob_kzg_proof(
            &ok,
            (const uint8_t *)(data + blob_offset),
            (const Bytes48 *)(data + commitment_offset),
            (const Bytes48 *)(data + proof_offset),
            &s
        );
    }
    return 0;
}
