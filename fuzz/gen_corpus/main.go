package main

import (
	"bytes"
	"log"
	"math/rand"
	"os"

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

func GenerateCorpusVerifyKZGProof(seed int64) {
	commitment := GetRandCommitment(seed + 0)
	z := GetRandFieldElement(seed + 1)
	y := GetRandFieldElement(seed + 2)
	proof := GetRandProof(seed + 3)

	data := bytes.Join([][]byte{commitment[:], z[:], y[:], proof[:]}, []byte{})
	err := os.WriteFile("../verify_kzg_proof/corpus/init", data, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

///////////////////////////////////////////////////////////////////////////////
// Entry point
///////////////////////////////////////////////////////////////////////////////

func main() {
	ret := ckzg.LoadTrustedSetupFile("../src/trusted_setup.txt")
	if ret != ckzg.C_KZG_OK {
		panic("failed to load trusted setup")
	}
	defer ckzg.FreeTrustedSetup()

	GenerateCorpusVerifyKZGProof(1)
}
