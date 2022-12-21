package main

import (
    "os"
    "bytes"
    "testing"

    "github.com/jtraglia/c-kzg-4844/bindings/go/types"
    "github.com/trailofbits/go-fuzz-utils"
    "github.com/stretchr/testify/require"
)

func GetTypeProvider(data []byte) (*go_fuzz_utils.TypeProvider, error) {
    tp, err := go_fuzz_utils.NewTypeProvider(data)
    if err != nil {
        return nil, err
    }
    return tp, nil
}

func TestMain(m *testing.M) {
    ret := LoadTrustedSetupFile("../../src/trusted_setup.txt")
    if ret != 0 {
        panic("Failed to load trusted setup")
    }
    code := m.Run()
    FreeTrustedSetup()
    os.Exit(code)
}

func FuzzBytesToG1(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }
        bytes, err := tp.GetNBytes(48)
        if err != nil {
            return
        }

        var bytes48 [48]byte
        copy(bytes48[:], bytes)

        g1, ret := BytesToG1(bytes48)
        t.Log(g1, ret)
    })
}

func FuzzBytesFromG1(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }
        g1Bytes, err := tp.GetNBytes(types.G1Size)
        if err != nil {
            return
        }

        var g1 [types.G1Size]byte
        copy(g1[:], g1Bytes)

        bytes := BytesFromG1(g1)
        t.Log(bytes)
    })
}

func FuzzBytesToBlsField(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }
        bytes, err := tp.GetNBytes(types.BytesPerFieldElement)
        if err != nil {
            return
        }

        var bytes32 [types.BytesPerFieldElement]byte
        copy(bytes32[:], bytes)

        blsField, ret := BytesToBlsField(bytes32)
        t.Log(blsField, ret)
    })
}

func FuzzComputeAggregateKzgProof(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }
        blobs := []types.Blob{}
        for {
            blobBytesPart, err := tp.GetNBytes(32)
            if err != nil {
                break
            }
            blobBytes := bytes.Repeat(blobBytesPart, 4096)
            require.Len(t, blobBytes, types.BlobSize)

            var blob types.Blob
            copy(blob[:], blobBytes)
            blobs = append(blobs, blob)
        }

        proof, ret := ComputeAggregateKzgProof(blobs)
        t.Log(proof, ret)
    })
}

func FuzzVerifyAggregateKzgProof(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }
        proofBytes, err := tp.GetNBytes(types.ProofSize)
        if err != nil {
            return
        }
        var proof types.Proof
        copy(proof[:], proofBytes)

        blobs := []types.Blob{}
        commitments := []types.Commitment{}
        for {
            blobBytesPart, err := tp.GetNBytes(32)
            if err != nil {
                break
            }
            blobBytes := bytes.Repeat(blobBytesPart, 4096)
            require.Len(t, blobBytes, types.BlobSize)
            commitmentBytes, err := tp.GetNBytes(types.CommitmentSize)
            if err != nil {
                break
            }

            var blob types.Blob
            copy(blob[:], blobBytes)
            blobs = append(blobs, blob)
            var commitment types.Commitment
            copy(commitment[:], commitmentBytes)
            commitments = append(commitments, commitment)
        }

        result, ret := VerifyAggregateKzgProof(blobs, commitments, proof)
        t.Log(result, ret)
    })
}

func FuzzBlobToKzgCommitment(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }
        blobBytesPart, err := tp.GetNBytes(32)
        if err != nil {
            return
        }
        blobBytes := bytes.Repeat(blobBytesPart, 4096)
        require.Len(t, blobBytes, types.BlobSize)

        var blob types.Blob
        copy(blob[:], blobBytes)

        commitment, ret := BlobToKzgCommitment(blob)
        t.Log(commitment, ret)
    })
}

func FuzzVerifyKzgProof(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if err != nil {
            return
        }
        commitmentBytes, err := tp.GetNBytes(types.CommitmentSize)
        if err != nil {
            return
        }
        zBytes, err := tp.GetNBytes(types.BytesPerFieldElement)
        if err != nil {
            return
        }
        yBytes, err := tp.GetNBytes(types.BytesPerFieldElement)
        if err != nil {
            return
        }
        proofBytes, err := tp.GetNBytes(types.ProofSize)
        if err != nil {
            return
        }

        var commitment types.Commitment
        copy(commitment[:], commitmentBytes)
        var z [types.BytesPerFieldElement]byte
        copy(z[:], zBytes)
        var y [types.BytesPerFieldElement]byte
        copy(y[:], yBytes)
        var proof types.Proof
        copy(proof[:], proofBytes)

        result, ret := VerifyKzgProof(commitment, z, y, proof)
        t.Log(result, ret)
    })
}
