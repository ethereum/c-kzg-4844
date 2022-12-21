package main

// #cgo CFLAGS: -g -I../inc -DFIELD_ELEMENTS_PER_BLOB=4096
// #cgo LDFLAGS: -L../lib -lblst
// #include <stdlib.h>
// #include "c_kzg_4844.h"
import "C"
import "fmt"
import "unsafe"

const blobSize = C.BYTES_PER_BLOB
const commitmentSize = C.sizeof_KZGCommitment
const proofSize = C.sizeof_KZGProof
const g1Size = C.sizeof_g1_t
const g2Size = C.sizeof_g2_t
const bytesPerFieldElement = C.BYTES_PER_FIELD_ELEMENT

type Blob [blobSize]byte
type Commitment [commitmentSize]byte
type Proof [proofSize]byte

var settings = C.KZGSettings{}

func main() {
    fmt.Println("Loading trusted setup")
    LoadTrustedSetupFile("../src/trusted_setup.txt")
    fmt.Println("Freeing trusted setup")
    FreeTrustedSetup()

    fmt.Printf("blobSize: %v\n", blobSize)
    fmt.Printf("commitmentSize: %v\n", commitmentSize)
    fmt.Printf("proofSize: %v\n", proofSize)
    fmt.Printf("g1Size: %v\n", g1Size)
    fmt.Printf("g2Size: %v\n", g2Size)
    fmt.Printf("bytesPerFieldElement: %v\n", bytesPerFieldElement)
}

/*
C_KZG_RET bytes_to_g1(
    g1_t* out,
    const uint8_t in[48]);
*/
func BytesToG1(bytes [48]byte) (C.g1_t, C.C_KZG_RET) {
    out := C.g1_t{}
    ret := C.bytes_to_g1(
        &out,
        (*C.uchar)(unsafe.Pointer(&bytes)))
    return out, ret
}

/*
void bytes_from_g1(
    uint8_t out[48],
    const g1_t *in);
*/
func BytesFromG1(g1 [g1Size]byte) [48]byte {
    var bytes [48]byte
    C.bytes_from_g1(
        (*C.uchar)(unsafe.Pointer(&bytes)),
        (*C.g1_t)(unsafe.Pointer(&g1)))
    return bytes
}

/*
C_KZG_RET bytes_to_bls_field(
    BLSFieldElement *out,
    const uint8_t in[BYTES_PER_FIELD_ELEMENT]);
*/
func BytesToBlsField(bytes [bytesPerFieldElement]byte) (C.BLSFieldElement, C.C_KZG_RET) {
    bls_field := C.BLSFieldElement{}
    ret := C.bytes_to_bls_field(
        &bls_field,
        (*C.uchar)(unsafe.Pointer(&bytes)))
    return bls_field, ret
}

/*
C_KZG_RET load_trusted_setup(
    KZGSettings *out,
    const uint8_t g1_bytes[], // n1 * 48 bytes
    size_t n1,
    const uint8_t g2_bytes[], // n2 * 96 bytes
    size_t n2);
*/
func LoadTrustedSetup(g1Bytes, g2Bytes []byte) C.C_KZG_RET {
    if len(g1Bytes)%48 != 0 {
        panic("len(g1Bytes) is not a multiple of 48")
    }
    if len(g2Bytes)%96 != 0 {
        panic("len(g2Bytes) is not a multiple of 96")
    }
    numG1Elements := len(g1Bytes) % 48
    numG2Elements := len(g1Bytes) % 96
    return C.load_trusted_setup(
        &settings,
        (*C.uchar)(unsafe.Pointer(&g1Bytes)),
        (C.size_t)(numG1Elements),
        (*C.uchar)(unsafe.Pointer(&g1Bytes)),
        (C.size_t)(numG2Elements))
}

/*
C_KZG_RET load_trusted_setup_file(
    KZGSettings *out,
    FILE *in);
*/
func LoadTrustedSetupFile(trustedSetupFile string) C.C_KZG_RET {
    fp := C.fopen(C.CString(trustedSetupFile), C.CString("rb"))
    if fp == nil {
        panic("Error reading trusted setup")
    }
    ret := C.load_trusted_setup_file(&settings, fp)
    C.fclose(fp)
    return ret
}

/*
void free_trusted_setup(
    KZGSettings *s);
*/
func FreeTrustedSetup() {
    C.free_trusted_setup(&settings)
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
    ret := C.compute_aggregate_kzg_proof(
        &proof,
        (*[blobSize]C.uchar)(unsafe.Pointer(&blobs)),
        (C.size_t)(len(blobs)),
        &settings)
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
        (*[blobSize]C.uchar)(unsafe.Pointer(&blobs)),
        (*C.KZGCommitment)(unsafe.Pointer(&commitments)),
        (C.size_t)(len(blobs)),
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
func VerifyKzgProof(commitment Commitment, z, y [32]byte, proof Proof) (C.bool, C.C_KZG_RET) {
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
