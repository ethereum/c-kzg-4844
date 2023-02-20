package cgokzg4844

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
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
// Test Helper Functions
///////////////////////////////////////////////////////////////////////////////

func getBlob(path string) Blob {
	inputBytes, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var blob Blob
	err = blob.UnmarshalText(inputBytes)
	if err != nil {
		panic(err)
	}
	return blob
}

func getBytes32(path string) Bytes32 {
	inputBytes, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var bytes32 Bytes32
	err = bytes32.UnmarshalText(inputBytes)
	if err != nil {
		panic(err)
	}
	return bytes32
}

func getBytes48(path string) Bytes48 {
	inputBytes, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var bytes48 Bytes48
	err = bytes48.UnmarshalText(inputBytes)
	if err != nil {
		panic(err)
	}
	return bytes48
}

func getBoolean(path string) bool {
	inputBytes, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return strings.Contains(string(inputBytes), "true")
}

///////////////////////////////////////////////////////////////////////////////
// Tests
///////////////////////////////////////////////////////////////////////////////

var (
	testDir                      = "../../tests"
	blobToKZGCommitmentTests     = filepath.Join(testDir, "blob_to_kzg_commitment/*")
	computeKZGProofTests         = filepath.Join(testDir, "compute_kzg_proof/*")
	computeBlobKZGProofTests     = filepath.Join(testDir, "compute_blob_kzg_proof/*")
	verifyKZGProofTests          = filepath.Join(testDir, "verify_kzg_proof/*")
	verifyBlobKZGProofTests      = filepath.Join(testDir, "verify_blob_kzg_proof/*")
	verifyBlobKZGProofBatchTests = filepath.Join(testDir, "verify_blob_kzg_proof_batch/*")
)

func TestBlobToKZGCommitment(t *testing.T) {
	tests, err := filepath.Glob(blobToKZGCommitmentTests)
	require.NoError(t, err)
	for _, test := range tests {
		blob := getBlob(filepath.Join(test, "blob.txt"))

		commitment, ret := BlobToKZGCommitment(blob)
		if ret == C_KZG_OK {
			expectedCommitment := KZGCommitment(getBytes48(filepath.Join(test, "commitment.txt")))
			require.Equal(t, commitment, expectedCommitment, test)
		} else {
			require.NoFileExists(t, filepath.Join(test, "commitment.txt"))
		}
	}
}

func TestComputeKZGProof(t *testing.T) {
	tests, err := filepath.Glob(computeKZGProofTests)
	require.NoError(t, err)
	for _, test := range tests {
		blob := getBlob(filepath.Join(test, "blob.txt"))
		inputPoint := getBytes32(filepath.Join(test, "input_point.txt"))

		proof, ret := ComputeKZGProof(blob, inputPoint)
		if ret == C_KZG_OK {
			expectedProof := KZGProof(getBytes48(filepath.Join(test, "proof.txt")))
			require.Equal(t, proof, expectedProof, test)
		} else {
			require.NoFileExists(t, filepath.Join(test, "proof.txt"))
		}
	}
}

func TestComputeBlobKZGProof(t *testing.T) {
	tests, err := filepath.Glob(computeBlobKZGProofTests)
	require.NoError(t, err)
	for _, test := range tests {
		blob := getBlob(filepath.Join(test, "blob.txt"))

		proof, ret := ComputeBlobKZGProof(blob)
		if ret == C_KZG_OK {
			expectedProof := KZGProof(getBytes48(filepath.Join(test, "proof.txt")))
			require.Equal(t, proof, expectedProof, test)
		} else {
			require.NoFileExists(t, filepath.Join(test, "proof.txt"))
		}
	}
}

func TestVerifyKZGProof(t *testing.T) {
	tests, err := filepath.Glob(verifyKZGProofTests)
	require.NoError(t, err)
	for _, test := range tests {
		commitment := getBytes48(filepath.Join(test, "commitment.txt"))
		inputPoint := getBytes32(filepath.Join(test, "input_point.txt"))
		claimedValue := getBytes32(filepath.Join(test, "claimed_value.txt"))
		proof := getBytes48(filepath.Join(test, "proof.txt"))

		ok, ret := VerifyKZGProof(commitment, inputPoint, claimedValue, proof)
		if ret == C_KZG_OK {
			expectedOk := getBoolean(filepath.Join(test, "ok.txt"))
			require.Equal(t, ok, expectedOk, test)
		} else {
			require.NoFileExists(t, filepath.Join(test, "ok.txt"))
		}
	}
}

func TestVerifyBlobKZGProof(t *testing.T) {
	tests, err := filepath.Glob(verifyBlobKZGProofTests)
	require.NoError(t, err)
	for _, test := range tests {
		blob := getBlob(filepath.Join(test, "blob.txt"))
		commitment := getBytes48(filepath.Join(test, "commitment.txt"))
		proof := getBytes48(filepath.Join(test, "proof.txt"))

		ok, ret := VerifyBlobKZGProof(blob, commitment, proof)
		if ret == C_KZG_OK {
			expectedOk := getBoolean(filepath.Join(test, "ok.txt"))
			require.Equal(t, ok, expectedOk, test)
		} else {
			require.NoFileExists(t, filepath.Join(test, "ok.txt"))
		}
	}
}

func TestVerifyBlobKZGProofBatch(t *testing.T) {
	tests, err := filepath.Glob(verifyBlobKZGProofBatchTests)
	require.NoError(t, err)
	for _, test := range tests {
		blobFiles, err := filepath.Glob(filepath.Join(test, "blobs/*"))
		require.NoError(t, err)
		blobs := make([]Blob, len(blobFiles))
		for i, blobFile := range blobFiles {
			blobs[i] = getBlob(blobFile)
		}
		commitmentFiles, err := filepath.Glob(filepath.Join(test, "commitments/*"))
		require.NoError(t, err)
		commitments := make([]Bytes48, len(commitmentFiles))
		for i, commitmentFile := range commitmentFiles {
			commitments[i] = getBytes48(commitmentFile)
		}
		proofFiles, err := filepath.Glob(filepath.Join(test, "proofs/*"))
		require.NoError(t, err)
		proofs := make([]Bytes48, len(proofFiles))
		for i, proofFile := range proofFiles {
			proofs[i] = getBytes48(proofFile)
		}
		require.Len(t, commitments, len(blobs))
		require.Len(t, proofs, len(blobs))

		ok, ret := VerifyBlobKZGProofBatch(blobs, commitments, proofs)
		if ret == C_KZG_OK {
			expectedOk := getBoolean(filepath.Join(test, "ok.txt"))
			require.Equal(t, ok, expectedOk, test)
		} else {
			require.NoFileExists(t, filepath.Join(test, "ok.txt"))
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// Benchmarks
///////////////////////////////////////////////////////////////////////////////

func Benchmark(b *testing.B) {
	const length = 64
	blobs := [length]Blob{}
	commitments := [length]Bytes48{}
	proofs := [length]Bytes48{}
	fields := [length]Bytes32{}
	for i := 0; i < length; i++ {
		blob := GetRandBlob(int64(i))
		commitment, ret := BlobToKZGCommitment(blob)
		require.Equal(b, ret, C_KZG_OK)
		proof, ret := ComputeBlobKZGProof(blob)
		require.Equal(b, ret, C_KZG_OK)

		blobs[i] = blob
		commitments[i] = Bytes48(commitment)
		proofs[i] = Bytes48(proof)
		fields[i] = GetRandFieldElement(int64(i))
	}

	///////////////////////////////////////////////////////////////////////////
	// Public functions
	///////////////////////////////////////////////////////////////////////////

	b.Run("BlobToKZGCommitment", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			BlobToKZGCommitment(blobs[0])
		}
	})

	b.Run("ComputeKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			ComputeKZGProof(blobs[0], fields[0])
		}
	})

	b.Run("ComputeBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			ComputeBlobKZGProof(blobs[0])
		}
	})

	b.Run("VerifyKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			VerifyKZGProof(commitments[0], fields[0], fields[1], proofs[0])
		}
	})

	b.Run("VerifyBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			VerifyBlobKZGProof(blobs[0], commitments[0], proofs[0])
		}
	})

	for i := 1; i <= len(blobs); i *= 2 {
		b.Run(fmt.Sprintf("VerifyBlobKZGProofBatch(count=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				VerifyBlobKZGProofBatch(blobs[:i], commitments[:i], proofs[:i])
			}
		})
	}

	///////////////////////////////////////////////////////////////////////////
	// Private functions
	///////////////////////////////////////////////////////////////////////////

	for i := 2; i <= 20; i += 2 {
		numBytes := int64(1 << i)
		bytes := make([]byte, numBytes)
		b.Run(fmt.Sprintf("sha256(size=%v)", HumanBytes(numBytes)), func(b *testing.B) {
			b.SetBytes(numBytes)
			for n := 0; n < b.N; n++ {
				sha256(bytes)
			}
		})
	}
}
