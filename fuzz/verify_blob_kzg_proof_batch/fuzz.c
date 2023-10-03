#include "../base_fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    initialize();
    size_t blobs_offset = 0;
    size_t commitments_offset = blobs_offset + s.bytes_per_blob;
    size_t proofs_offset = commitments_offset + BYTES_PER_COMMITMENT;
    size_t input_size = proofs_offset + BYTES_PER_PROOF;
    size_t count = size / input_size;

    bool ok;
    verify_blob_kzg_proof_batch(
        &ok,
        (const uint8_t *)(data + blobs_offset * count),
        (const Bytes48 *)(data + commitments_offset * count),
        (const Bytes48 *)(data + proofs_offset * count),
        count,
        &s
    );
    return 0;
}
