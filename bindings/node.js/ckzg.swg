/* File : ckzg.swg */
%module ckzg

%{
#include "../../src/c_kzg_4844.h"
%}

extern C_KZG_RET load_trusted_setup(KZGSettings *out,
    FILE *in);

extern void free_trusted_setup(
    KZGSettings *s);

extern C_KZG_RET compute_aggregate_kzg_proof(KZGProof *out,
    const Polynomial blobs[],
    size_t n,
    const KZGSettings *s);

extern C_KZG_RET verify_aggregate_kzg_proof(bool *out,
    const Polynomial blobs[],
    const KZGCommitment expected_kzg_commitments[],
    size_t n,
    const KZGProof *kzg_aggregated_proof,
    const KZGSettings *s);

extern void blob_to_kzg_commitment(KZGCommitment *out,
    const BLSFieldElement blob[FIELD_ELEMENTS_PER_BLOB],
    const KZGSettings *s);

extern C_KZG_RET verify_kzg_proof(bool *out,
    const KZGCommitment *polynomial_kzg,
    const BLSFieldElement *z,
    const BLSFieldElement *y,
    const KZGProof *kzg_proof,
    const KZGSettings *s);
