package cgokzg4844

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	ret := LoadTrustedSetupFile("../../src/trusted_setup.txt")
	if ret != 0 {
		panic("failed to load trusted setup")
	}
	defer FreeTrustedSetup()
	code := m.Run()
	os.Exit(code)
}

///////////////////////////////////////////////////////////////////////////////
// Helper Functions
///////////////////////////////////////////////////////////////////////////////

func (b *Blob) UnmarshalText(input []byte) error {
	blobBytes, err := hex.DecodeString(string(input))
	if err != nil {
		return err
	}
	if len(blobBytes) != len(b) {
		return errors.New("invalid Blob")
	}
	copy(b[:], blobBytes)
	return nil
}

func (p *KZGProof) UnmarshalText(input []byte) error {
	proofBytes, err := hex.DecodeString(string(input))
	if err != nil {
		return err
	}
	if len(proofBytes) != len(p) {
		return errors.New("invalid KZGProof")
	}
	copy(p[:], proofBytes)
	return nil
}

func (c *KZGCommitment) UnmarshalText(input []byte) error {
	commitmentBytes, err := hex.DecodeString(string(input))
	if err != nil {
		return err
	}
	if len(commitmentBytes) != len(c) {
		return errors.New("invalid KZGCommitment")
	}
	copy(c[:], commitmentBytes)
	return nil
}

func (f *Bytes32) UnmarshalText(input []byte) error {
	bytes, err := hex.DecodeString(string(input))
	if err != nil {
		return err
	}
	if len(bytes) != len(f) {
		return errors.New("invalid Bytes32")
	}
	copy(f[:], bytes)
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// Tests
///////////////////////////////////////////////////////////////////////////////

func TestComputeAggregateKZGProof(t *testing.T) {
	type Test struct {
		TestCases []struct {
			Polynomials []Blob    `json:"Polynomials"`
			Proof       Bytes48   `json:"Proof"`
			Commitments []Bytes48 `json:"Commitments"`
		}
	}

	testFile, err := os.Open("../rust/test_vectors/public_agg_proof.json")
	require.NoError(t, err)
	defer testFile.Close()
	test := Test{}
	err = json.NewDecoder(testFile).Decode(&test)
	require.NoError(t, err)

	for _, tc := range test.TestCases {
		proof, ret := ComputeAggregateKZGProof(tc.Polynomials)
		require.Zero(t, ret)
		require.Equal(t, tc.Proof[:], proof[:])
		for i := range tc.Polynomials {
			commitment, ret := BlobToKZGCommitment(tc.Polynomials[i])
			require.Equal(t, C_KZG_OK, ret)
			require.Equal(t, tc.Commitments[i][:], commitment[:])
		}
	}
}

func TestVerifyKZGProof(t *testing.T) {
	type Test struct {
		TestCases []struct {
			Polynomial   Blob    `json:"Polynomial"`
			Proof        Bytes48 `json:"Proof"`
			Commitment   Bytes48 `json:"Commitment"`
			InputPoint   Bytes32 `json:"InputPoint"`
			ClaimedValue Bytes32 `json:"ClaimedValue"`
		}
	}

	testFile, err := os.Open("../rust/test_vectors/public_verify_kzg_proof.json")
	require.NoError(t, err)
	defer testFile.Close()
	test := Test{}
	err = json.NewDecoder(testFile).Decode(&test)
	require.NoError(t, err)

	for _, tc := range test.TestCases {
		result, ret := VerifyKZGProof(tc.Commitment, tc.InputPoint, tc.ClaimedValue, tc.Proof)
		require.Equal(t, C_KZG_OK, ret)
		require.True(t, result)
	}
}

///////////////////////////////////////////////////////////////////////////////
// Benchmarks
///////////////////////////////////////////////////////////////////////////////

func Benchmark(b *testing.B) {
	const length = 64
	blobs := [length]Blob{}
	commitments := [length]Bytes48{}
	for i := 0; i < length; i++ {
		blobs[i][0] = byte(i)
		commitment, _ := BlobToKZGCommitment(blobs[i])
		commitments[i] = Bytes48(commitment)
	}
	z := Bytes32{1, 2, 3}
	y := Bytes32{4, 5, 6}
	trustedProof, _ := ComputeAggregateKZGProof(blobs[:1])
	proof := Bytes48(trustedProof)

	b.Run("BlobToKZGCommitment", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, ret := BlobToKZGCommitment(blobs[0])
			require.Equal(b, C_KZG_OK, ret)
		}
	})

	b.Run("ComputeKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, ret := ComputeKZGProof(blobs[0], z)
			require.Equal(b, C_KZG_OK, ret)
		}
	})

	b.Run("VerifyKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, ret := VerifyKZGProof(commitments[0], z, y, proof)
			require.Equal(b, C_KZG_OK, ret)
		}
	})

	for i := 1; i <= len(blobs); i *= 2 {
		b.Run(fmt.Sprintf("ComputeAggregateKZGProof(blobs=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, ret := ComputeAggregateKZGProof(blobs[:i])
				require.Equal(b, C_KZG_OK, ret)
			}
		})
	}

	for i := 1; i <= len(blobs); i *= 2 {
		b.Run(fmt.Sprintf("VerifyAggregateKZGProof(blobs=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, ret := VerifyAggregateKZGProof(blobs[:i], commitments[:i], proof)
				require.Equal(b, C_KZG_OK, ret)
			}
		})
	}
}
