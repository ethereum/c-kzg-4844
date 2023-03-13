#include "../base_fuzz.h"

static const size_t BLOBS_OFFSET = 0;
static const size_t COMMITMENTS_OFFSET = BLOBS_OFFSET + BYTES_PER_BLOB;
static const size_t PROOFS_OFFSET = COMMITMENTS_OFFSET + BYTES_PER_COMMITMENT;
static const size_t INPUT_SIZE = PROOFS_OFFSET + BYTES_PER_PROOF;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    initialize();
    size_t count = size / INPUT_SIZE;
    bool ok;
    verify_blob_kzg_proof_batch(
        &ok,
        (const Blob *)(data + BLOBS_OFFSET * count),
        (const Bytes48 *)(data + COMMITMENTS_OFFSET * count),
        (const Bytes48 *)(data + PROOFS_OFFSET * count),
        count,
        &s
    );
    return 0;
}
