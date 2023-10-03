#include "../base_fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    initialize();
    size_t commitment_offset = 0;
    size_t z_offset = commitment_offset + BYTES_PER_COMMITMENT;
    size_t y_offset = z_offset + BYTES_PER_FIELD_ELEMENT;
    size_t proof_offset = y_offset + BYTES_PER_FIELD_ELEMENT;
    size_t input_size = proof_offset + BYTES_PER_PROOF;

    if (size == input_size) {
        bool ok;
        verify_kzg_proof(
            &ok,
            (const Bytes48 *)(data + commitment_offset),
            (const Bytes32 *)(data + z_offset),
            (const Bytes32 *)(data + y_offset),
            (const Bytes48 *)(data + proof_offset),
            &s
        );
    }
    return 0;
}
