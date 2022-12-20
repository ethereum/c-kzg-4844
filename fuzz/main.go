package main

// #cgo CFLAGS: -g -Wall -I../inc -DFIELD_ELEMENTS_PER_BLOB=4096
// #cgo LDFLAGS: -L../lib -lblst
// #include <stdlib.h>
// #include "c_kzg_4844.h"
import "C"
import "unsafe"

type Blob []byte
type Commitment []byte
type Proof []byte

var settings = C.KZGSettings{}

func main() {
    LoadTrustedSetupFile("../src/trusted_setup.txt")
    FreeTrustedSetup()
}

/*
C_KZG_RET load_trusted_setup_file(
    KZGSettings *out,
    FILE *in);
*/
func LoadTrustedSetupFile(trusted_setup_file string) C.C_KZG_RET {
    fp := C.fopen(C.CString(trusted_setup_file), C.CString("rb"))
    ret := C.load_trusted_setup_file(&settings, fp)
    C.fclose(fp)
    return ret
}

/*
void free_trusted_setup(
    KZGSettings *s);
*/
func FreeTrustedSetup() {
    C.free_trusted_setup(&settings);
}

/*
C_KZG_RET compute_aggregate_kzg_proof(
    KZGProof *out,
    const Blob blobs[],
    size_t n,
    const KZGSettings *s);
*/
func ComputeAggregateKzgProof(blobs []Blob) (C.KZGProof, C.C_KZG_RET) {
  proof := C.KZGProof{}
  b := unsafe.Pointer(&blobs)
  ret := C.compute_aggregate_kzg_proof(&proof, (*C.Blob)(b), (C.ulong)(len(blobs)), &settings)
  return proof, ret
}

/*
C_KZG_RET verify_aggregate_kzg_proof(
    bool *out,
    const Blob blobs[],
    const KZGCommitment expected_kzg_commitments[],
    size_t n,
    const KZGProof *kzg_aggregated_proof,
    const KZGSettings *s);
*/
func VerifyAggregateKzgProof(blobs []Blob, commitments []Commitment, proof Proof) (C.bool, C.C_KZG_RET) {
  if len(blobs) != len(commitments) {
      panic("len(blobs) != len(commitments)")
  }
  var result C.bool
  ret := C.verify_aggregate_kzg_proof(
      &result,
      (*C.Blob)(unsafe.Pointer(&blobs)),
      (*C.KZGCommitment)(unsafe.Pointer(&commitments)),
      (C.ulong)(len(blobs)),
      (*C.KZGProof)(unsafe.Pointer(&proof)),
      &settings)
  return result, ret
}

/*
C_KZG_RET blob_to_kzg_commitment(
    KZGCommitment *out,
    const Blob blob,
    const KZGSettings *s);
*/
func BlobToKzgCommitment(blob Blob) (C.KZGCommitment, C.C_KZG_RET) {
  commitment := C.KZGCommitment{}
  ret := C.blob_to_kzg_commitment(
      &commitment,
      (*C.uchar)(unsafe.Pointer(&blob)),
      &settings)
  return commitment, ret
}

/*
C_KZG_RET verify_kzg_proof(
    bool *out,
    const KZGCommitment *polynomial_kzg,
    const uint8_t z[BYTES_PER_FIELD_ELEMENT],
    const uint8_t y[BYTES_PER_FIELD_ELEMENT],
    const KZGProof *kzg_proof,
    const KZGSettings *s);
*/
func VerifyKzgProof(commitment Commitment, z, y []byte, proof Proof) (C.bool, C.C_KZG_RET) {
  var result C.bool
  ret := C.verify_kzg_proof(
      &result,
      (*C.KZGCommitment)(unsafe.Pointer(&commitment)),
      (*C.uchar)(unsafe.Pointer(&z)),
      (*C.uchar)(unsafe.Pointer(&y)),
      (*C.KZGProof)(unsafe.Pointer(&proof)),
      &settings)
  return result, ret
}
