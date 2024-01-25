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
	err := LoadTrustedSetupFile("../../src/trusted_setup.txt")
	if err != nil {
		panic("failed to load trusted setup")
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

func getRandBlob(seed int64) Blob {
	blob := Blob{}
	for i := 0; i < BytesPerBlob; i += BytesPerFieldElement {
		fieldElementBytes := getRandFieldElement(seed + int64(i))
		copy(blob[i:i+BytesPerFieldElement], fieldElementBytes[:])
	}
	return blob
}

func getPartialCells(cells *[CellsPerBlob]Cell, i int) []Cell {
	partialCells := []Cell{}
	for j := range cells {
		if j%i != 0 {
			partialCells = append(partialCells, cells[j])
		}
	}
	return partialCells
}

func getColumns(rows []*[CellsPerBlob]Cell, numCols int) []Cell {
	var cells []Cell
	for i := range rows {
		for j := 0; j < numCols; j++ {
			cells = append(cells, rows[i][j])

		}
	}
	return cells
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

			var blob Blob
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

			var blob Blob
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

			var blob Blob
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

			var blob Blob
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

func TestVerifyCell(t *testing.T) {
	blob := getRandBlob(0)

	commitment, err := BlobToKZGCommitment(blob)
	require.NoError(t, err)
	cells, err := ComputeCells(&blob, 0)
	require.NoError(t, err)

	for i := range cells {
		ok, err := VerifyCellProof(Bytes48(commitment), &cells[i])
		require.NoError(t, err)
		require.True(t, ok)
	}
}

func TestVerifyCells(t *testing.T) {
	blob := getRandBlob(0)
	commitment, err := BlobToKZGCommitment(blob)
	require.NoError(t, err)
	cells, err := ComputeCells(&blob, 0)
	require.NoError(t, err)

	commitments := []Bytes48{Bytes48(commitment)}
	ok, err := VerifyCellProofBatch(commitments, cells[:])
	require.NoError(t, err)
	require.True(t, ok)
}

func TestVerifyCellsMultiBlobs(t *testing.T) {
	blob1 := getRandBlob(0)
	blob2 := getRandBlob(1)

	commitment1, err := BlobToKZGCommitment(blob1)
	require.NoError(t, err)
	commitment2, err := BlobToKZGCommitment(blob2)
	require.NoError(t, err)

	cells1, err := ComputeCells(&blob1, 0)
	require.NoError(t, err)
	cells2, err := ComputeCells(&blob2, 1)
	require.NoError(t, err)

	commitments := []Bytes48{Bytes48(commitment1), Bytes48(commitment2)}

	var cells []Cell
	for _, Cell := range cells1 {
		cells = append(cells, Cell)
	}
	for _, Cell := range cells2 {
		cells = append(cells, Cell)
	}

	ok, err := VerifyCellProofBatch(commitments, cells)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestRecoverHalfMissing(t *testing.T) {
	blob := getRandBlob(0)
	cells, err := ComputeCells(&blob, 0)
	require.NoError(t, err)
	partial := getPartialCells(cells, 2)
	recovered, err := RecoverCells(partial)
	require.NoError(t, err)
	require.Equal(t, recovered, cells)
}

func TestRecoverNoMissing(t *testing.T) {
	blob := getRandBlob(0)
	cells, err := ComputeCells(&blob, 0)
	require.NoError(t, err)
	recovered, err := RecoverCells(cells[:])
	require.NoError(t, err)
	require.Equal(t, recovered, cells)
}

///////////////////////////////////////////////////////////////////////////////
// Benchmarks
///////////////////////////////////////////////////////////////////////////////

func Benchmark(b *testing.B) {
	const n int64 = 16
	blobs := &[n]Blob{}
	commitments := &[n]Bytes48{}
	proofs := &[n]Bytes48{}
	fields := &[n]Bytes32{}
	blobCells := &[n]*[CellsPerBlob]Cell{}

	for i := int64(0); i < n; i++ {
		blobs[i] = getRandBlob(i)

		commitment, err := BlobToKZGCommitment(blobs[i])
		require.NoError(b, err)
		commitments[i] = Bytes48(commitment)

		proof, err := ComputeBlobKZGProof(blobs[i], commitments[i])
		require.NoError(b, err)
		proofs[i] = Bytes48(proof)

		blobCells[i], err = ComputeCells(&blobs[i], uint32(i))
	}

	b.Run("BlobToKZGCommitment", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := BlobToKZGCommitment(blobs[0])
			require.NoError(b, err)
		}
	})

	b.Run("ComputeKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _, err := ComputeKZGProof(blobs[0], fields[0])
			require.NoError(b, err)
		}
	})

	b.Run("ComputeBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := ComputeBlobKZGProof(blobs[0], commitments[0])
			require.NoError(b, err)
		}
	})

	b.Run("VerifyKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := VerifyKZGProof(commitments[0], fields[0], fields[1], proofs[0])
			require.NoError(b, err)
		}
	})

	b.Run("VerifyBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := VerifyBlobKZGProof(blobs[0], commitments[0], proofs[0])
			require.NoError(b, err)
		}
	})

	for i := 1; i <= len(blobs); i *= 2 {
		b.Run(fmt.Sprintf("VerifyBlobKZGProofBatch(count=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, err := VerifyBlobKZGProofBatch(blobs[:i], commitments[:i], proofs[:i])
				require.NoError(b, err)
			}
		})
	}

	b.Run("ComputeCells", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := ComputeCells(&blobs[0], 0)
			require.NoError(b, err)
		}
	})

	b.Run("CellsToBlob", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := CellsToBlob(blobCells[0])
			require.NoError(b, err)
		}
	})

	for i := 2; i <= 8; i *= 2 {
		percentMissing := (1.0 / float64(i)) * 100
		partial := getPartialCells(blobCells[0], i)
		b.Run(fmt.Sprintf("RecoverCells(missing=%2.1f%%)", percentMissing), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, err := RecoverCells(partial)
				require.NoError(b, err)
			}
		})
	}

	b.Run("VerifyCellProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := VerifyCellProof(commitments[0], &blobCells[0][0])
			require.NoError(b, err)
		}
	})

	b.Run("VerifyCellProofBatch", func(b *testing.B) {
		var cells []Cell
		for _, blobCell := range blobCells {
			for _, Cell := range blobCell {
				cells = append(cells, Cell)
			}
		}
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			ok, err := VerifyCellProofBatch(commitments[:], cells)
			require.NoError(b, err)
			require.True(b, ok)
		}
	})

	for i := 1; i <= 128; i *= 2 {
		cells := getColumns(blobCells[:], i)
		b.Run(fmt.Sprintf("VerifyColumns(count=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				ok, err := VerifyCellProofBatch(commitments[:], cells)
				require.NoError(b, err)
				require.True(b, ok)
			}
		})
	}
}
