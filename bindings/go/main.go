package main

// #cgo CFLAGS: -g -Wall -I../../inc -DFIELD_ELEMENTS_PER_BLOB=4096
// #cgo LDFLAGS: -L../../lib -lblst
// #include <stdlib.h>
// #include "../../src/c_kzg_4844.h"
// #include "../../src/c_kzg_4844.c"
import "C"
import (
    "unsafe"
    "github.com/jtraglia/c-kzg-4844/bindings/go/types"
)

var loaded = false
var settings = C.KZGSettings{}

/*
BytesToG1 is the binding for:
    C_KZG_RET bytes_to_g1(
        g1_t* out,
        const uint8_t in[48]);
*/
func BytesToG1(bytes [48]byte) (types.G1, types.CKzgRet) {
    out := types.G1{}
    ret := C.bytes_to_g1(
        (*C.g1_t)(unsafe.Pointer(&out)),
        (*C.uchar)(unsafe.Pointer(&bytes)))
    return out, types.CKzgRet(ret)
}

/*
BytesFromG1 is the binding for:
    void bytes_from_g1(
        uint8_t out[48],
        const g1_t *in);
*/
func BytesFromG1(g1 types.G1) [48]byte {
    var bytes [48]byte
    C.bytes_from_g1(
        (*C.uchar)(unsafe.Pointer(&bytes)),
        (*C.g1_t)(unsafe.Pointer(&g1)))
    return bytes
}

/*
BytesToBlsField is the binding for:
    C_KZG_RET bytes_to_bls_field(
        BLSFieldElement *out,
        const uint8_t in[BYTES_PER_FIELD_ELEMENT]);
*/
func BytesToBlsField(bytes [types.BytesPerFieldElement]byte) (types.FieldElement, types.CKzgRet) {
    blsField := types.FieldElement{}
    ret := C.bytes_to_bls_field(
        (*C.BLSFieldElement)(unsafe.Pointer(&blsField)),
        (*C.uint8_t)(unsafe.Pointer(&bytes)))
    return blsField, types.CKzgRet(ret)
}

/*
LoadTrustedSetup is the binding for:
    C_KZG_RET load_trusted_setup(
        KZGSettings *out,
        const uint8_t g1_bytes[], // n1 * 48 bytes
        size_t n1,
        const uint8_t g2_bytes[], // n2 * 96 bytes
        size_t n2);
*/
func LoadTrustedSetup(g1Bytes, g2Bytes []byte) types.CKzgRet {
    if loaded == true {
        panic("trusted setup is already loaded")
    }
    if len(g1Bytes)%48 != 0 {
        panic("len(g1Bytes) is not a multiple of 48")
    }
    if len(g2Bytes)%96 != 0 {
        panic("len(g2Bytes) is not a multiple of 96")
    }
    numG1Elements := len(g1Bytes) % 48
    numG2Elements := len(g1Bytes) % 96
    ret := C.load_trusted_setup(
        &settings,
        (*C.uint8_t)(unsafe.Pointer(&g1Bytes)),
        (C.size_t)(numG1Elements),
        (*C.uint8_t)(unsafe.Pointer(&g1Bytes)),
        (C.size_t)(numG2Elements))
    if ret == 0 {
        loaded = true
    }
    return types.CKzgRet(ret)
}

/*
LoadTrustedSetupFile is the binding for:
    C_KZG_RET load_trusted_setup_file(
        KZGSettings *out,
        FILE *in);
*/
func LoadTrustedSetupFile(trustedSetupFile string) types.CKzgRet {
    if loaded == true {
        panic("trusted setup is already loaded")
    }
    fp := C.fopen(C.CString(trustedSetupFile), C.CString("rb"))
    if fp == nil {
        panic("Error reading trusted setup")
    }
    ret := C.load_trusted_setup_file(&settings, fp)
    C.fclose(fp)
    if ret == 0 {
        loaded = true
    }
    return types.CKzgRet(ret)
}

/*
FreeTrustedSetup is the binding for:
    void free_trusted_setup(
        KZGSettings *s);
*/
func FreeTrustedSetup() {
    if loaded == false {
        panic("trusted setup isn't loaded")
    }
    C.free_trusted_setup(&settings)
}

/*
ComputeAggregateKzgProof is the binding for:
    C_KZG_RET compute_aggregate_kzg_proof(
        KZGProof *out,
        const Blob blobs[],
        size_t n,
        const KZGSettings *s);
*/
func ComputeAggregateKzgProof(blobs []types.Blob) (types.Proof, types.CKzgRet) {
    proof := types.Proof{}
    ret := C.compute_aggregate_kzg_proof(
        (*C.KZGProof)(unsafe.Pointer(&proof)),
        (*C.Blob)(unsafe.Pointer(&blobs)),
        (C.size_t)(len(blobs)),
        &settings)
    return proof, types.CKzgRet(ret)
}

/*
VerifyAggregateKzgProof is the binding for:
    C_KZG_RET verify_aggregate_kzg_proof(
        bool *out,
        const Blob blobs[],
        const KZGCommitment expected_kzg_commitments[],
        size_t n,
        const KZGProof *kzg_aggregated_proof,
        const KZGSettings *s);
*/
func VerifyAggregateKzgProof(blobs []types.Blob, commitments []types.Commitment, proof types.Proof) (bool, types.CKzgRet) {
    if len(blobs) != len(commitments) {
        panic("len(blobs) != len(commitments)")
    }
    var result C.bool
    ret := C.verify_aggregate_kzg_proof(
        &result,
        (*C.Blob)(unsafe.Pointer(&blobs)),
        (*C.KZGCommitment)(unsafe.Pointer(&commitments)),
        (C.size_t)(len(blobs)),
        (*C.KZGProof)(unsafe.Pointer(&proof)),
        &settings)
    return bool(result), types.CKzgRet(ret)
}

/*
BlobToKzgCommitment is the binding for:
    C_KZG_RET blob_to_kzg_commitment(
        KZGCommitment *out,
        const Blob blob,
        const KZGSettings *s);
*/
func BlobToKzgCommitment(blob types.Blob) (types.Commitment, types.CKzgRet) {
    commitment := types.Commitment{}
    ret := C.blob_to_kzg_commitment(
        (*C.KZGCommitment)(unsafe.Pointer(&commitment)),
        (*C.uint8_t)(unsafe.Pointer(&blob)),
        &settings)
    return commitment, types.CKzgRet(ret)
}

/*
VerifyKzgProof is the binding for:
    C_KZG_RET verify_kzg_proof(
        bool *out,
        const KZGCommitment *polynomial_kzg,
        const uint8_t z[BYTES_PER_FIELD_ELEMENT],
        const uint8_t y[BYTES_PER_FIELD_ELEMENT],
        const KZGProof *kzg_proof,
        const KZGSettings *s);
*/
func VerifyKzgProof(commitment types.Commitment, z, y types.FieldElement, proof types.Proof) (bool, types.CKzgRet) {
    var result C.bool
    ret := C.verify_kzg_proof(
        &result,
        (*C.KZGCommitment)(unsafe.Pointer(&commitment)),
        (*C.uint8_t)(unsafe.Pointer(&z)),
        (*C.uint8_t)(unsafe.Pointer(&y)),
        (*C.KZGProof)(unsafe.Pointer(&proof)),
        &settings)
    return bool(result), types.CKzgRet(ret)
}
