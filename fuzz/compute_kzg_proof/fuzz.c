#include "../base_fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    initialize();
    size_t blob_offset = 0;
    size_t z_offset = blob_offset + s.bytes_per_blob;
    size_t input_size = z_offset + BYTES_PER_FIELD_ELEMENT;

    if (size == input_size) {
        KZGProof proof;
        Bytes32 y;
        compute_kzg_proof(
            &proof,
            &y,
            (const uint8_t *)(data + blob_offset),
            (const Bytes32 *)(data + z_offset),
            &s
        );
    }
    return 0;
}
