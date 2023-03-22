package main

import (
	"encoding/hex"
	"fmt"

	ckzg "github.com/ethereum/c-kzg-4844/bindings/go"
)

var TrustedSetupPath = "../../../src/trusted_setup.txt"

func main() {
	ret := ckzg.LoadTrustedSetupFile(TrustedSetupPath)
	if ret != ckzg.C_KZG_OK {
		panic("failed to load trusted setup")
	}
	defer ckzg.FreeTrustedSetup()

	blob := ckzg.Blob{1, 2, 3}
	commitment, ret := ckzg.BlobToKZGCommitment(blob)
	if ret != ckzg.C_KZG_OK {
		panic("failed to get commitment for blob")
	}
	fmt.Println(hex.EncodeToString(commitment[:]))
}
