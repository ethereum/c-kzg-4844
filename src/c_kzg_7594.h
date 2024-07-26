/**
 * @file c_kzg_7594.h
 *
 * Minimal interface required for EIP-7594.
 */
#ifndef C_KZG_7594_H
#define C_KZG_7594_H

#include "c_kzg_4844.h"
#include "common.h"

/** A single cell for a blob. */
typedef struct {
    uint8_t bytes[BYTES_PER_CELL];
} Cell;

C_KZG_RET compute_cells_and_kzg_proofs(
    Cell *cells, KZGProof *proofs, const Blob *blob, const KZGSettings *s
);

C_KZG_RET recover_cells_and_kzg_proofs(
    Cell *recovered_cells,
    KZGProof *recovered_proofs,
    const uint64_t *cell_indices,
    const Cell *cells,
    size_t num_cells,
    const KZGSettings *s
);

C_KZG_RET verify_cell_kzg_proof_batch(
    bool *ok,
    const Bytes48 *commitments_bytes,
    const uint64_t *cell_indices,
    const Cell *cells,
    const Bytes48 *proofs_bytes,
    size_t num_cells,
    const KZGSettings *s
);

#endif /* C_KZG_7594_H */
