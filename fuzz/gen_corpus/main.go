package main

import (
	"bytes"
	"math/rand"
	"os"
	"path"

	ckzg "github.com/ethereum/c-kzg-4844/bindings/go"
)

///////////////////////////////////////////////////////////////////////////////
// Helper functions
///////////////////////////////////////////////////////////////////////////////

func GetRandFieldElement(seed int64) ckzg.Bytes32 {
	rand.Seed(seed)
	bytes := make([]byte, 31)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("failed to get random field element")
	}

	// This leaves the last byte in fieldElementBytes as
	// zero, which guarantees it's a canonical field element.
	var fieldElementBytes ckzg.Bytes32
	copy(fieldElementBytes[:], bytes)
	return fieldElementBytes
}

func GetRandCommitment(seed int64) ckzg.KZGCommitment {
	commitment, ret := ckzg.BlobToKZGCommitment(GetRandBlob(seed))
	if ret != ckzg.C_KZG_OK {
		panic("failed to get random commitment")
	}
	return commitment
}

func GetRandProof(seed int64) ckzg.KZGProof {
	commitment := ckzg.Bytes48(GetRandCommitment(seed))
	proof, ret := ckzg.ComputeBlobKZGProof(GetRandBlob(seed), commitment)
	if ret != ckzg.C_KZG_OK {
		panic("failed to get random proof")
	}
	return proof
}

func GetRandBlob(seed int64) ckzg.Blob {
	var blob ckzg.Blob
	for i := 0; i < ckzg.BytesPerBlob; i += ckzg.BytesPerFieldElement {
		fieldElementBytes := GetRandFieldElement(seed + int64(i))
		copy(blob[i:i+ckzg.BytesPerFieldElement], fieldElementBytes[:])
	}
	return blob
}

///////////////////////////////////////////////////////////////////////////////
// Generators
///////////////////////////////////////////////////////////////////////////////

func GenerateCorpusVerifyKZGProof() {
	commitment := GetRandCommitment(0)
	z := GetRandFieldElement(1)
	y := GetRandFieldElement(2)
	proof := GetRandProof(3)

	dir := "../verify_kzg_proof/corpus"
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		panic(err)
	}

	data := bytes.Join([][]byte{commitment[:], z[:], y[:], proof[:]}, []byte{})
	err = os.WriteFile(path.Join(dir, "init"), data, 0644)
	if err != nil {
		panic(err)
	}
}

func GenerateCorpusVerifyBlobKZGProof() {
	blob := GetRandBlob(0)
	commitment := GetRandCommitment(1)
	proof := GetRandProof(2)

	dir := "../verify_blob_kzg_proof/corpus"
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		panic(err)
	}

	data := bytes.Join([][]byte{blob[:], commitment[:], proof[:]}, []byte{})
	err = os.WriteFile(path.Join(dir, "init"), data, 0644)
	if err != nil {
		panic(err)
	}
}

func GenerateCorpusVerifyBlobKZGProofBatch() {
	const n = 3
	var blobs [n][]byte
	var commitments [n][]byte
	var proofs [n][]byte

	for i := range blobs {
		blob := GetRandBlob(int64(i) + 0)
		commitment := GetRandCommitment(int64(i) + 1)
		proof := GetRandProof(int64(i) + 2)

		blobs[i] = blob[:]
		commitments[i] = commitment[:]
		proofs[i] = proof[:]
	}

	dir := "../verify_blob_kzg_proof_batch/corpus"
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		panic(err)
	}

	blobsBytes := bytes.Join(blobs[:], []byte{})
	commitmentsBytes := bytes.Join(commitments[:], []byte{})
	proofsBytes := bytes.Join(proofs[:], []byte{})
	data := bytes.Join([][]byte{blobsBytes, commitmentsBytes, proofsBytes}, []byte{})
	err = os.WriteFile(path.Join(dir, "init"), data, 0644)
	if err != nil {
		panic(err)
	}
}

///////////////////////////////////////////////////////////////////////////////
// Entry point
///////////////////////////////////////////////////////////////////////////////

func main() {
	ret := ckzg.LoadTrustedSetupFile("../../src/trusted_setup.txt")
	if ret != ckzg.C_KZG_OK {
		panic("failed to load trusted setup")
	}
	defer ckzg.FreeTrustedSetup()

	GenerateCorpusVerifyKZGProof()
	GenerateCorpusVerifyBlobKZGProof()
	GenerateCorpusVerifyBlobKZGProofBatch()
}
