package cgokzg4844

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
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

func (f *Bytes48) UnmarshalText(input []byte) error {
	bytes, err := hex.DecodeString(string(input))
	if err != nil {
		return err
	}
	if len(bytes) != len(f) {
		return errors.New("invalid Bytes48")
	}
	copy(f[:], bytes)
	return nil
}

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

func GetRandFieldElement(seed int64) Bytes32 {
	rand.Seed(seed)
	bytes := make([]byte, 31)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("failed to get random field element")
	}

	// This leaves the last byte in fieldElementBytes as
	// zero, which guarantees it's a canonical field element.
	var fieldElementBytes Bytes32
	copy(fieldElementBytes[:], bytes)
	return fieldElementBytes
}

func GetRandBlob(seed int64) Blob {
	var blob Blob
	for i := 0; i < BytesPerBlob; i += BytesPerFieldElement {
		fieldElementBytes := GetRandFieldElement(seed + int64(i))
		copy(blob[i:i+BytesPerFieldElement], fieldElementBytes[:])
	}
	return blob
}

/*
HumanBytes will convert an integer to a human-readable value. Adapted from:
https://programming.guide/go/formatting-byte-size-to-human-readable-format.html
*/
func HumanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%v%cB", float64(b)/float64(div), "KMGTPE"[exp])
}

///////////////////////////////////////////////////////////////////////////////
// Tests
///////////////////////////////////////////////////////////////////////////////

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
	proofs := [length]Bytes48{}
	commitments := [length]Bytes48{}
	z := Bytes32{1, 2, 3}
	y := Bytes32{4, 5, 6}
	for i := 0; i < length; i++ {
		blobs[i] = GetRandBlob(int64(i))
		commitment, _ := BlobToKZGCommitment(blobs[i])
		commitments[i] = Bytes48(commitment)
		trustedProof, _ := ComputeBlobKZGProof(blobs[i])
		proofs[i] = Bytes48(trustedProof)
	}

	///////////////////////////////////////////////////////////////////////////
	// Public functions
	///////////////////////////////////////////////////////////////////////////

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
			_, ret := VerifyKZGProof(commitments[0], z, y, proofs[0])
			require.Equal(b, C_KZG_OK, ret)
		}
	})

	b.Run("ComputeBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, ret := ComputeBlobKZGProof(blobs[0])
			require.Equal(b, C_KZG_OK, ret)
		}
	})

	b.Run("VerifyBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, ret := VerifyBlobKZGProof(blobs[0], commitments[0], proofs[0])
			require.Equal(b, C_KZG_OK, ret)
		}
	})

	for i := 1; i <= len(blobs); i *= 2 {
		b.Run(fmt.Sprintf("VerifyBlobKZGProofBatch(blobs=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, ret := VerifyBlobKZGProofBatch(blobs[:i], commitments[:i], proofs[:i])
				require.Equal(b, C_KZG_OK, ret)
			}
		})
	}

	///////////////////////////////////////////////////////////////////////////
	// Private functions
	///////////////////////////////////////////////////////////////////////////

	for i := 2; i <= 20; i += 2 {
		var numBytes = int64(1 << i)
		var bytes = make([]byte, numBytes)
		b.Run(fmt.Sprintf("sha256(size=%v)", HumanBytes(numBytes)), func(b *testing.B) {
			b.SetBytes(numBytes)
			for n := 0; n < b.N; n++ {
				sha256(bytes)
			}
		})
	}
}
