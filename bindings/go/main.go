package cgokzg4844

// #cgo CFLAGS: -I${SRCDIR}/../../src
// #cgo CFLAGS: -I${SRCDIR}/blst_headers
// #cgo CFLAGS: -DFIELD_ELEMENTS_PER_BLOB=4096
// #include "c_kzg_4844.c"
import "C"

import (
	"unsafe"

	// So its functions are available during compilation.
	_ "github.com/supranational/blst/bindings/go"
)

const (
	BytesPerBlob         = C.BYTES_PER_BLOB
	BytesPerCommitment   = C.BYTES_PER_COMMITMENT
	BytesPerFieldElement = C.BYTES_PER_FIELD_ELEMENT
	BytesPerProof        = C.BYTES_PER_PROOF
	FieldElementsPerBlob = C.FIELD_ELEMENTS_PER_BLOB
)

type (
	CKzgRet         int
	Blob            [BytesPerBlob]byte
	KZGCommitment   [BytesPerCommitment]byte
	BLSFieldElement [BytesPerFieldElement]byte
	KZGProof        [BytesPerProof]byte
)

const (
	C_KZG_OK      CKzgRet = C.C_KZG_OK
	C_KZG_BADARGS CKzgRet = C.C_KZG_BADARGS
	C_KZG_ERROR   CKzgRet = C.C_KZG_ERROR
	C_KZG_MALLOC  CKzgRet = C.C_KZG_MALLOC
)

var (
	loaded   = false
	settings = C.KZGSettings{}
)

/*
LoadTrustedSetup is the binding for:

	C_KZG_RET load_trusted_setup(
	    KZGSettings *out,
	    const uint8_t *g1_bytes,
	    size_t n1,
	    const uint8_t *g2_bytes,
	    size_t n2);
*/
func LoadTrustedSetup(g1Bytes, g2Bytes []byte) CKzgRet {
	if loaded {
		panic("trusted setup is already loaded")
	}
	if len(g1Bytes)%48 != 0 {
		panic("len(g1Bytes) is not a multiple of 48")
	}
	if len(g2Bytes)%96 != 0 {
		panic("len(g2Bytes) is not a multiple of 96")
	}
	numG1Elements := len(g1Bytes) / 48
	numG2Elements := len(g2Bytes) / 96
	ret := C.load_trusted_setup(
		&settings,
		*(**C.uint8_t)(unsafe.Pointer(&g1Bytes)),
		(C.size_t)(numG1Elements),
		*(**C.uint8_t)(unsafe.Pointer(&g2Bytes)),
		(C.size_t)(numG2Elements))
	if CKzgRet(ret) == C_KZG_OK {
		loaded = true
	}
	return CKzgRet(ret)
}

/*
LoadTrustedSetupFile is the binding for:

	C_KZG_RET load_trusted_setup_file(
	    KZGSettings *out,
	    FILE *in);
*/
func LoadTrustedSetupFile(trustedSetupFile string) CKzgRet {
	if loaded {
		panic("trusted setup is already loaded")
	}
	fp := C.fopen(C.CString(trustedSetupFile), C.CString("rb"))
	if fp == nil {
		panic("error reading trusted setup")
	}
	ret := C.load_trusted_setup_file(&settings, fp)
	C.fclose(fp)
	if CKzgRet(ret) == C_KZG_OK {
		loaded = true
	}
	return CKzgRet(ret)
}

/*
FreeTrustedSetup is the binding for:

	void free_trusted_setup(
	    KZGSettings *s);
*/
func FreeTrustedSetup() {
	if !loaded {
		panic("trusted setup isn't loaded")
	}
	C.free_trusted_setup(&settings)
	loaded = false
}

/*
ComputeAggregateKZGProof is the binding for:

	C_KZG_RET compute_aggregate_kzg_proof(
	    KZGProof *out,
	    const Blob *blobs,
	    size_t n,
	    const KZGSettings *s);
*/
func ComputeAggregateKZGProof(blobs []Blob) (KZGProof, CKzgRet) {
	if !loaded {
		panic("trusted setup isn't loaded")
	}
	proof := KZGProof{}
	ret := C.compute_aggregate_kzg_proof(
		(*C.KZGProof)(unsafe.Pointer(&proof)),
		*(**C.Blob)(unsafe.Pointer(&blobs)),
		(C.size_t)(len(blobs)),
		&settings)
	return proof, CKzgRet(ret)
}

/*
VerifyAggregateKZGProof is the binding for:

	C_KZG_RET verify_aggregate_kzg_proof(
	    bool *out,
	    const Blob *blobs,
	    const KZGCommitment *expected_kzg_commitments,
	    size_t n,
	    const KZGProof *kzg_aggregated_proof,
	    const KZGSettings *s);
*/
func VerifyAggregateKZGProof(blobs []Blob, expectedKzgCommitments []KZGCommitment, kzgAggregatedProof KZGProof) (bool, CKzgRet) {
	if !loaded {
		panic("trusted setup isn't loaded")
	}
	if len(blobs) != len(expectedKzgCommitments) {
		panic("len(blobs) != len(commitments)")
	}
	var result C.bool
	ret := C.verify_aggregate_kzg_proof(
		&result,
		*(**C.Blob)(unsafe.Pointer(&blobs)),
		*(**C.KZGCommitment)(unsafe.Pointer(&expectedKzgCommitments)),
		(C.size_t)(len(blobs)),
		(*C.KZGProof)(unsafe.Pointer(&kzgAggregatedProof)),
		&settings)
	return bool(result), CKzgRet(ret)
}

/*
BlobToKZGCommitment is the binding for:

	C_KZG_RET blob_to_kzg_commitment(
	    KZGCommitment *out,
	    const Blob *blob,
	    const KZGSettings *s);
*/
func BlobToKZGCommitment(blob Blob) (KZGCommitment, CKzgRet) {
	if !loaded {
		panic("trusted setup isn't loaded")
	}
	commitment := KZGCommitment{}
	ret := C.blob_to_kzg_commitment(
		(*C.KZGCommitment)(unsafe.Pointer(&commitment)),
		(*C.Blob)(unsafe.Pointer(&blob)),
		&settings)
	return commitment, CKzgRet(ret)
}

/*
VerifyKZGProof is the binding for:

	C_KZG_RET verify_kzg_proof(
	    bool *out,
	    const KZGCommitment *polynomial_kzg,
	    const BLSFieldElement *z,
	    const BLSFieldElement *y,
	    const KZGProof *kzg_proof,
	    const KZGSettings *s);
*/
func VerifyKZGProof(polynomialKzg KZGCommitment, z, y BLSFieldElement, kzgProof KZGProof) (bool, CKzgRet) {
	if !loaded {
		panic("trusted setup isn't loaded")
	}
	var result C.bool
	ret := C.verify_kzg_proof(
		&result,
		(*C.KZGCommitment)(unsafe.Pointer(&polynomialKzg)),
		(*C.BLSFieldElement)(unsafe.Pointer(&z)),
		(*C.BLSFieldElement)(unsafe.Pointer(&y)),
		(*C.KZGProof)(unsafe.Pointer(&kzgProof)),
		&settings)
	return bool(result), CKzgRet(ret)
}
