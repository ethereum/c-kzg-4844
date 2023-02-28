package cgokzg4844

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
	bytes, err := hex.DecodeString(string(input[2:]))
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
	bytes, err := hex.DecodeString(string(input[2:]))
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
	blobBytes, err := hex.DecodeString(string(input[2:]))
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

var (
	testDir                      = "../../tests"
	blobToKZGCommitmentTests     = filepath.Join(testDir, "blob_to_kzg_commitment/*/*/*")
	computeKZGProofTests         = filepath.Join(testDir, "compute_kzg_proof/*/*/*")
	computeBlobKZGProofTests     = filepath.Join(testDir, "compute_blob_kzg_proof/*/*/*")
	verifyKZGProofTests          = filepath.Join(testDir, "verify_kzg_proof/*/*/*")
	verifyBlobKZGProofTests      = filepath.Join(testDir, "verify_blob_kzg_proof/*/*/*")
	verifyBlobKZGProofBatchTests = filepath.Join(testDir, "verify_blob_kzg_proof_batch/*/*/*")
)

func TestBlobToKZGCommitment(t *testing.T) {
	type Test struct {
		Input struct {
			Blob Blob `yaml:"blob"`
		}
		Output *Bytes48 `yaml:"output"`
	}

	tests, err := filepath.Glob(blobToKZGCommitmentTests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Log(testPath)
		testFile, err := os.Open(testPath)
		require.NoError(t, err)
		test := Test{}
		err = yaml.NewDecoder(testFile).Decode(&test)
		require.NoError(t, testFile.Close())
		require.NoError(t, err)

		commitment, ret := BlobToKZGCommitment(test.Input.Blob)
		if ret == C_KZG_OK {
			require.NotNil(t, test.Output)
			require.Equal(t, test.Output[:], commitment[:])
		} else {
			require.Nil(t, test.Output)
		}
	}
}

func TestComputeKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Blob Blob    `yaml:"blob"`
			Z    Bytes32 `yaml:"z"`
		}
		Output *Bytes48 `yaml:"output"`
	}

	tests, err := filepath.Glob(computeKZGProofTests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Log(testPath)
		testFile, err := os.Open(testPath)
		require.NoError(t, err)
		test := Test{}
		err = yaml.NewDecoder(testFile).Decode(&test)
		require.NoError(t, testFile.Close())
		require.NoError(t, err)

		proof, ret := ComputeKZGProof(test.Input.Blob, test.Input.Z)
		if ret == C_KZG_OK {
			require.NotNil(t, test.Output)
			require.Equal(t, test.Output[:], proof[:])
		} else {
			require.Nil(t, test.Output)
		}
	}
}

func TestComputeBlobKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Blob Blob `yaml:"blob"`
		}
		Output *Bytes48 `yaml:"output"`
	}

	tests, err := filepath.Glob(computeBlobKZGProofTests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Log(testPath)
		testFile, err := os.Open(testPath)
		require.NoError(t, err)
		test := Test{}
		err = yaml.NewDecoder(testFile).Decode(&test)
		require.NoError(t, testFile.Close())
		require.NoError(t, err)

		proof, ret := ComputeBlobKZGProof(test.Input.Blob)
		if ret == C_KZG_OK {
			require.NotNil(t, test.Output)
			require.Equal(t, test.Output[:], proof[:])
		} else {
			require.Nil(t, test.Output)
		}
	}
}

func TestVerifyKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Commitment Bytes48 `yaml:"commitment"`
			Z          Bytes32 `yaml:"z"`
			Y          Bytes32 `yaml:"y"`
			Proof      Bytes48 `yaml:"proof"`
		}
		Output *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyKZGProofTests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Log(testPath)
		testFile, err := os.Open(testPath)
		require.NoError(t, err)
		test := Test{}
		err = yaml.NewDecoder(testFile).Decode(&test)
		require.NoError(t, testFile.Close())
		require.NoError(t, err)

		valid, ret := VerifyKZGProof(
			test.Input.Commitment,
			test.Input.Z,
			test.Input.Y,
			test.Input.Proof)
		if ret == C_KZG_OK {
			require.NotNil(t, test.Output)
			require.Equal(t, *test.Output, valid)
		} else {
			require.Nil(t, test.Output)
		}
	}
}

func TestVerifyBlobKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Blob       Blob    `yaml:"blob"`
			Commitment Bytes48 `yaml:"commitment"`
			Proof      Bytes48 `yaml:"proof"`
		}
		Output *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyBlobKZGProofTests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Log(testPath)
		testFile, err := os.Open(testPath)
		require.NoError(t, err)
		test := Test{}
		err = yaml.NewDecoder(testFile).Decode(&test)
		require.NoError(t, testFile.Close())
		require.NoError(t, err)

		valid, ret := VerifyBlobKZGProof(
			test.Input.Blob,
			test.Input.Commitment,
			test.Input.Proof)
		if ret == C_KZG_OK {
			require.NotNil(t, test.Output)
			require.Equal(t, *test.Output, valid)
		} else {
			require.Nil(t, test.Output)
		}
	}
}

func TestVerifyBlobKZGProofBatch(t *testing.T) {
	type Test struct {
		Input struct {
			Blobs       []Blob    `yaml:"blobs"`
			Commitments []Bytes48 `yaml:"commitments"`
			Proofs      []Bytes48 `yaml:"proofs"`
		}
		Output *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyBlobKZGProofBatchTests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Log(testPath)
		testFile, err := os.Open(testPath)
		require.NoError(t, err)
		test := Test{}
		err = yaml.NewDecoder(testFile).Decode(&test)
		require.NoError(t, testFile.Close())
		require.NoError(t, err)

		valid, ret := VerifyBlobKZGProofBatch(
			test.Input.Blobs,
			test.Input.Commitments,
			test.Input.Proofs)
		if ret == C_KZG_OK {
			require.NotNil(t, test.Output)
			require.Equal(t, *test.Output, valid)
		} else {
			require.Nil(t, test.Output)
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
