package ckzg4844

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestMain(m *testing.M) {

	if err := LoadTrustedSetupFile("../../src/trusted_setup.txt"); err != nil {
		panic(fmt.Sprintf("failed to load trusted setup: %v", err))
	}
	defer FreeTrustedSetup()
	code := m.Run()
	os.Exit(code)
}

///////////////////////////////////////////////////////////////////////////////
// Helper Functions
///////////////////////////////////////////////////////////////////////////////

func getRandFieldElement(seed int64) Bytes32 {
	rand.Seed(seed)
	bytes := make([]byte, 31)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("failed to get random field element")
	}

	// This leaves the first byte in fieldElementBytes as
	// zero, which guarantees it's a canonical field element.
	var fieldElementBytes Bytes32
	copy(fieldElementBytes[1:], bytes)
	return fieldElementBytes
}

func fillBlobRandom(blob *Blob, seed int64) {
	for i := 0; i < BytesPerBlob; i += BytesPerFieldElement {
		fieldElementBytes := getRandFieldElement(seed + int64(i))
		copy(blob[i:i+BytesPerFieldElement], fieldElementBytes[:])
	}
}

///////////////////////////////////////////////////////////////////////////////
// Reference Tests
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
			Blob string `yaml:"blob"`
		}
		Output *Bytes48 `yaml:"output"`
	}

	tests, err := filepath.Glob(blobToKZGCommitmentTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			blob := new(Blob)
			err = blob.UnmarshalText([]byte(test.Input.Blob))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			commitment, err := BlobToKZGCommitment(blob)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, test.Output[:], commitment[:])
			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestComputeKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Blob string `yaml:"blob"`
			Z    string `yaml:"z"`
		}
		Output *[]string `yaml:"output"`
	}

	tests, err := filepath.Glob(computeKZGProofTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			blob := new(Blob)
			err = blob.UnmarshalText([]byte(test.Input.Blob))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var z Bytes32
			err = z.UnmarshalText([]byte(test.Input.Z))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			proof, y, err := ComputeKZGProof(blob, z)
			if err == nil {
				require.NotNil(t, test.Output)
				var expectedProof Bytes48
				err = expectedProof.UnmarshalText([]byte((*test.Output)[0]))
				require.NoError(t, err)
				require.Equal(t, expectedProof[:], proof[:])
				var expectedY Bytes32
				err = expectedY.UnmarshalText([]byte((*test.Output)[1]))
				require.NoError(t, err)
				require.Equal(t, expectedY[:], y[:])
			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestComputeBlobKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Blob       string `yaml:"blob"`
			Commitment string `yaml:"commitment"`
		}
		Output *Bytes48 `yaml:"output"`
	}

	tests, err := filepath.Glob(computeBlobKZGProofTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			blob := new(Blob)
			err = blob.UnmarshalText([]byte(test.Input.Blob))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var commitment Bytes48
			err = commitment.UnmarshalText([]byte(test.Input.Commitment))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			proof, err := ComputeBlobKZGProof(blob, commitment)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, test.Output[:], proof[:])
			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestVerifyKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Commitment string `yaml:"commitment"`
			Z          string `yaml:"z"`
			Y          string `yaml:"y"`
			Proof      string `yaml:"proof"`
		}
		Output *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyKZGProofTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			var commitment Bytes48
			err = commitment.UnmarshalText([]byte(test.Input.Commitment))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var z Bytes32
			err = z.UnmarshalText([]byte(test.Input.Z))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var y Bytes32
			err = y.UnmarshalText([]byte(test.Input.Y))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var proof Bytes48
			err = proof.UnmarshalText([]byte(test.Input.Proof))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			valid, err := VerifyKZGProof(commitment, z, y, proof)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, *test.Output, valid)
			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestVerifyBlobKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Blob       string `yaml:"blob"`
			Commitment string `yaml:"commitment"`
			Proof      string `yaml:"proof"`
		}
		Output *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyBlobKZGProofTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			var blob = new(Blob)
			err = blob.UnmarshalText([]byte(test.Input.Blob))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var commitment Bytes48
			err = commitment.UnmarshalText([]byte(test.Input.Commitment))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			var proof Bytes48
			err = proof.UnmarshalText([]byte(test.Input.Proof))
			if err != nil {
				require.Nil(t, test.Output)
				return
			}

			valid, err := VerifyBlobKZGProof(blob, commitment, proof)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, *test.Output, valid)
			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestVerifyBlobKZGProofBatch(t *testing.T) {
	type Test struct {
		Input struct {
			Blobs       []string `yaml:"blobs"`
			Commitments []string `yaml:"commitments"`
			Proofs      []string `yaml:"proofs"`
		}
		Output *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyBlobKZGProofBatchTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			var blobs []Blob
			for _, b := range test.Input.Blobs {
				var blob Blob
				err = blob.UnmarshalText([]byte(b))
				if err != nil {
					require.Nil(t, test.Output)
					return
				}
				blobs = append(blobs, blob)
			}

			var commitments []Bytes48
			for _, c := range test.Input.Commitments {
				var commitment Bytes48
				err = commitment.UnmarshalText([]byte(c))
				if err != nil {
					require.Nil(t, test.Output)
					return
				}
				commitments = append(commitments, commitment)
			}

			var proofs []Bytes48
			for _, p := range test.Input.Proofs {
				var proof Bytes48
				err = proof.UnmarshalText([]byte(p))
				if err != nil {
					require.Nil(t, test.Output)
					return
				}
				proofs = append(proofs, proof)
			}

			valid, err := VerifyBlobKZGProofBatch(blobs, commitments, proofs)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, *test.Output, valid)
			} else {
				require.Nil(t, test.Output)
			}
		})
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
		var blob Blob
		fillBlobRandom(&blob, int64(i))
		commitment, err := BlobToKZGCommitment(&blob)
		require.NoError(b, err)
		proof, err := ComputeBlobKZGProof(&blob, Bytes48(commitment))
		require.NoError(b, err)

		blobs[i] = blob
		commitments[i] = Bytes48(commitment)
		proofs[i] = Bytes48(proof)
		fields[i] = getRandFieldElement(int64(i))
	}

	b.Run("BlobToKZGCommitment", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			BlobToKZGCommitment(&blobs[0])
		}
	})

	b.Run("ComputeKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			ComputeKZGProof(&blobs[0], fields[0])
		}
	})

	b.Run("ComputeBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			ComputeBlobKZGProof(&blobs[0], commitments[0])
		}
	})

	b.Run("VerifyKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			VerifyKZGProof(commitments[0], fields[0], fields[1], proofs[0])
		}
	})

	b.Run("VerifyBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			VerifyBlobKZGProof(&blobs[0], commitments[0], proofs[0])
		}
	})

	for i := 1; i <= len(blobs); i *= 2 {
		b.Run(fmt.Sprintf("VerifyBlobKZGProofBatch(count=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				VerifyBlobKZGProofBatch(blobs[:i], commitments[:i], proofs[:i])
			}
		})
	}
}
