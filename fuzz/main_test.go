package main

import (
    "os"
    "bytes"
    "testing"

    "github.com/trailofbits/go-fuzz-utils"
)

func GetTypeProvider(data []byte) (*go_fuzz_utils.TypeProvider, error) {
    tp, err := go_fuzz_utils.NewTypeProvider(data)
    if err != nil {
        return nil, err
    }
    return tp, nil
}

func TestMain(m *testing.M) {
    ret := LoadTrustedSetupFile("../src/trusted_setup.txt")
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
        if (err != nil) {
            return
        }
        bytes, err := tp.GetNBytes(48)
        if (err != nil) {
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
        if (err != nil) {
            return
        }
        g1, err := tp.GetNBytes(144)
        if (err != nil) {
            return
        }

        bytes := BytesFromG1(g1)
        t.Log(bytes)
    })
}

func FuzzBytesToBlsField(f *testing.F) { 
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if (err != nil) {
            return
        }
        bytes, err := tp.GetNBytes(32)
        if (err != nil) {
            return
        }
        var bytes32 [32]byte
        copy(bytes32[:], bytes)

        bls_field, ret := BytesToBlsField(bytes32)
        t.Log(bls_field, ret)
    })
}

func FuzzComputeAggregateKzgProof(f *testing.F) { 
    f.Fuzz(func(t *testing.T, data []byte, count uint) {
        tp, err := GetTypeProvider(data)
        if (err != nil) {
            return
        }
        blobs := []Blob{}
        for i := 0; uint(i) < count; i++ {
            blob_part, err := tp.GetNBytes(32)
            if (err != nil) {
                return
            }
            blob := bytes.Repeat(blob_part, 4096)
            blobs = append(blobs, blob)
        }

        proof, ret := ComputeAggregateKzgProof(blobs)
        t.Log(proof, ret)
    })
}

func FuzzVerifyAggregateKzgProof(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte, count uint) {
        tp, err := GetTypeProvider(data)
        if (err != nil) {
            return
        }
        blobs := []Blob{}
        for i := 0; uint(i) < count; i++ {
            blob_part, err := tp.GetNBytes(32)
            if (err != nil) {
                return
            }
            blob := bytes.Repeat(blob_part, 4096)
            blobs = append(blobs, blob)
        }
        commitments := []Commitment{}
        for i := 0; uint(i) < count; i++ {
            commitment, err := tp.GetNBytes(144)
            if (err != nil) {
                return
            }
            commitments = append(commitments, commitment)
        }
        proof, err := tp.GetNBytes(144)
        if (err != nil) {
            return
        }

        result, ret := VerifyAggregateKzgProof(blobs, commitments, proof)
        t.Log(result, ret)
    })
}

func FuzzBlobToKzgCommitment(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if (err != nil) {
            return
        }
        blob_part, err := tp.GetNBytes(32)
        if (err != nil) {
            return
        }

        blob := bytes.Repeat(blob_part, 4096)
        commitment, ret := BlobToKzgCommitment(blob)
        t.Log(commitment, ret)
    })
}

func FuzzVerifyKzgProof(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        tp, err := GetTypeProvider(data)
        if (err != nil) {
            return
        }
        commitment, err := tp.GetNBytes(144)
        if (err != nil) {
            return
        }
        z, err := tp.GetNBytes(32)
        if (err != nil) {
            return
        }
        y, err := tp.GetNBytes(32)
        if (err != nil) {
            return
        }
        proof, err := tp.GetNBytes(144)
        if (err != nil) {
            return
        }

        result, ret := VerifyKzgProof(commitment, z, y, proof)
        t.Log(result, ret)
    })
}
