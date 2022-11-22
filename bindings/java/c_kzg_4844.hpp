#ifndef ___C_KZG_4844_HPP___
#define ___C_KZG_4844_HPP___

#include <vector>

#include "c_kzg_4844.h"
#include "bls12_381.hpp"
#include "setup.hpp"
#include "exception.hpp"

// TODO: make it work

KZGSetup load_trusted_setup_wrap(const char *file)
{
  KZGSettings *out = malloc(sizeof(KZGSettings));

  FILE *f = fopen(file, "r");

  CKZG_TRY(load_trusted_setup(out, f));

  return KZGSetup();
}

void free_trusted_setup_wrap(KZGSetup *s)
{
  KZGSettings s_;
  CKZG_TRY(free_trusted_setup(s_))
}

G1 compute_aggregate_kzg_proof_wrap(const Blob blobs[], size_t n, const KZGSetup *s)
{
  uint8_t out[48];
  KZGProof f;
  KZGSettings s_;
  CKZG_TRY(compute_aggregate_kzg_proof(&f, blobs, n, s_))
  bytes_from_g1(out, &f);
  return G1::from_bytes(out)
}

bool verify_aggregate_kzg_proof_wrap(const Blob blobs[],
                                     const G1 expected_kzg_commitments[],
                                     size_t n,
                                     const G1 *kzg_aggregated_proof,
                                     const KZGSetup *s)
{
  KZGCommitment expected_kzg_commitments_[];
  KZGProof kzg_aggregated_proof_;
  KZGSettings s_;
  bool out;
  CKZG_TRY(verify_aggregate_kzg_proof(&out, blobs, expected_kzg_commitments_, n, kzg_aggregated_proof, s_))
  return out;
}

G1 blob_to_kzg_commitment_wrap(const Blob blob, const KZGSetup *s)
{
  KZGSettings s_;
  uint8_t out[48];
  KZGCommitment c;
  blob_to_kzg_commitment(&c, blob, s_);
  bytes_from_g1(out, &c);
  return G1::from_bytes(out)
}

bool verify_kzg_proof_wrap(const G1 *polynomial_kzg,
                              const uint8_t z[BYTES_PER_FIELD_ELEMENT],
                              const uint8_t y[BYTES_PER_FIELD_ELEMENT],
                              const G1 *kzg_proof,
                              const KZGSetup *s)
{
  KZGCommitment commitment;
  KZGProof proof;
  KZGSettings s_;
  bool out;
  CKZG_TRY(verify_kzg_proof(&out, &commitment, z, y, &proof, s_))
  return out;
}

#endif