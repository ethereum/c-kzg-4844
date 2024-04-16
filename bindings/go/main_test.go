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

func getPartialCells(cells [CellsPerBlob]Cell, i int) ([]uint64, []Cell) {
	cellIds := []uint64{}
	partialCells := []Cell{}
	for j := range cells {
		if j%i != 0 {
			cellIds = append(cellIds, uint64(j))
			partialCells = append(partialCells, cells[j])
		}
	}
	return cellIds, partialCells
}

func getColumns(cellRows [][CellsPerBlob]Cell, proofRows [][CellsPerBlob]Bytes48, numCols int) ([]uint64, []uint64, []Cell, []Bytes48) {
	var rowIndices []uint64
	var columnIndices []uint64
	var cells []Cell
	var cellProofs []Bytes48
	for i := range cellRows {
		for j := 0; j < numCols; j++ {
			rowIndices = append(rowIndices, uint64(i))
			columnIndices = append(columnIndices, uint64(j))
			cells = append(cells, cellRows[i][j])
			cellProofs = append(cellProofs, proofRows[i][j])
		}
	}
	return rowIndices, columnIndices, cells, cellProofs
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

func TestVerifyCell(t *testing.T) {
	var blob Blob
	fillBlobRandom(&blob, 0)

	commitment, err := BlobToKZGCommitment(&blob)
	require.NoError(t, err)
	cells, proofs, err := ComputeCellsAndProofs(&blob)
	require.NoError(t, err)

	for i := range cells {
		ok, err := VerifyCellProof(Bytes48(commitment), uint64(i), cells[i], Bytes48(proofs[i]))
		require.NoError(t, err)
		require.True(t, ok)
	}
}

func TestVerifyCells(t *testing.T) {
	var blob Blob
	fillBlobRandom(&blob, 0)
	commitment, err := BlobToKZGCommitment(&blob)
	require.NoError(t, err)
	cells, proofs, err := ComputeCellsAndProofs(&blob)
	require.NoError(t, err)

	commitments := []Bytes48{Bytes48(commitment)}
	var rowIndices, columnIndices []uint64
	for i := uint64(0); i < CellsPerBlob; i++ {
		rowIndices = append(rowIndices, 0)
		columnIndices = append(columnIndices, i)
	}
	var proofsBytes []Bytes48
	for i := uint64(0); i < CellsPerBlob; i++ {
		proofsBytes = append(proofsBytes, Bytes48(proofs[i]))
	}
	ok, err := VerifyCellProofBatch(commitments, rowIndices, columnIndices, cells[:], proofsBytes[:])
	require.NoError(t, err)
	require.True(t, ok)
}

func TestVerifyCellsMultiBlobs(t *testing.T) {
	var blob1, blob2 Blob
	fillBlobRandom(&blob1, 0)
	fillBlobRandom(&blob2, 0)

	commitment1, err := BlobToKZGCommitment(&blob1)
	require.NoError(t, err)
	commitment2, err := BlobToKZGCommitment(&blob2)
	require.NoError(t, err)

	cells1, proofs1, err := ComputeCellsAndProofs(&blob1)
	require.NoError(t, err)
	cells2, proofs2, err := ComputeCellsAndProofs(&blob2)
	require.NoError(t, err)

	commitments := []Bytes48{Bytes48(commitment1), Bytes48(commitment2)}

	var rowIndices, columnIndices []uint64
	for i := uint64(0); i < CellsPerBlob; i++ {
		rowIndices = append(rowIndices, 0)
		columnIndices = append(columnIndices, i)
	}
	for i := uint64(0); i < CellsPerBlob; i++ {
		rowIndices = append(rowIndices, 1)
		columnIndices = append(columnIndices, i)
	}

	var cells []Cell
	for _, cell := range cells1 {
		cells = append(cells, cell)
	}
	for _, cell := range cells2 {
		cells = append(cells, cell)
	}

	var proofs []Bytes48
	for _, proof := range proofs1 {
		proofs = append(proofs, Bytes48(proof))
	}
	for _, proof := range proofs2 {
		proofs = append(proofs, Bytes48(proof))
	}

	ok, err := VerifyCellProofBatch(commitments, rowIndices, columnIndices, cells, proofs)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestRecoverHalfMissing(t *testing.T) {
	var blob Blob
	fillBlobRandom(&blob, 0)
	cells, _, err := ComputeCellsAndProofs(&blob)
	require.NoError(t, err)
	cellIds, partialCells := getPartialCells(cells, 2)
	recovered, err := RecoverPolynomial(cellIds, partialCells)
	require.NoError(t, err)
	require.Equal(t, recovered, cells)
}

func TestRecoverNoMissing(t *testing.T) {
	var blob Blob
	fillBlobRandom(&blob, 0)
	cells, _, err := ComputeCellsAndProofs(&blob)
	require.NoError(t, err)
	var cellIds []uint64
	for i := uint64(0); i < CellsPerBlob; i++ {
		cellIds = append(cellIds, i)
	}
	recovered, err := RecoverPolynomial(cellIds, cells[:])
	require.NoError(t, err)
	require.Equal(t, recovered, cells)
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
	blobCells := [length][CellsPerBlob]Cell{}
	blobCellProofs := [length][CellsPerBlob]Bytes48{}

	for i := 0; i < length; i++ {
		var blob Blob
		fillBlobRandom(&blob, int64(i))
		commitment, err := BlobToKZGCommitment(&blob)
		require.NoError(b, err)
		proof, err := ComputeBlobKZGProof(&blob, Bytes48(commitment))
		require.NoError(b, err)
		proofs[i] = Bytes48(proof)

		tProofs := [CellsPerBlob]KZGProof{}
		blobCells[i], tProofs, err = ComputeCellsAndProofs(&blobs[i])
		require.NoError(b, err)
		blobCellProofs[i] = [CellsPerBlob]Bytes48{}
		for j, p := range tProofs {
			blobCellProofs[i][j] = Bytes48(p)
		}
	}

	b.Run("BlobToKZGCommitment", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := BlobToKZGCommitment(&blobs[0])
			require.NoError(b, err)
		}
	})

	b.Run("ComputeKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _, err := ComputeKZGProof(&blobs[0], fields[0])
			require.NoError(b, err)
		}
	})

	b.Run("ComputeBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := ComputeBlobKZGProof(&blobs[0], commitments[0])
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
			_, err := VerifyBlobKZGProof(&blobs[0], commitments[0], proofs[0])
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
			_, err := ComputeCells(&blobs[0])
			require.NoError(b, err)
		}
	})

	b.Run("ComputeCellsAndProofs", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _, err := ComputeCellsAndProofs(&blobs[0])
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
		cellIds, partial := getPartialCells(blobCells[0], i)
		b.Run(fmt.Sprintf("RecoverPolynomial(missing=%2.1f%%)", percentMissing), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, err := RecoverPolynomial(cellIds, partial)
				require.NoError(b, err)
			}
		})
	}

	b.Run("VerifyCellProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := VerifyCellProof(commitments[0], 0, blobCells[0][0], blobCellProofs[0][0])
			require.NoError(b, err)
		}
	})

	b.Run("VerifyCellProofBatch", func(b *testing.B) {
		var rowIndices []uint64
		var columnIndices []uint64
		var cells []Cell
		var cellProofs []Bytes48
		for rowIndex, blobCell := range blobCells {
			for columnIndex, cell := range blobCell {
				rowIndices = append(rowIndices, uint64(rowIndex))
				columnIndices = append(columnIndices, uint64(columnIndex))
				cells = append(cells, cell)
				cellProofs = append(cellProofs, blobCellProofs[rowIndex][columnIndex])
			}
		}
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			ok, err := VerifyCellProofBatch(commitments[:], rowIndices, columnIndices, cells, cellProofs)
			require.NoError(b, err)
			require.True(b, ok)
		}
	})

	for i := 1; i <= 128; i *= 2 {
		rowIndices, columnIndices, cells, cellProofs := getColumns(blobCells[:], blobCellProofs[:], i)
		b.Run(fmt.Sprintf("VerifyColumns(count=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				ok, err := VerifyCellProofBatch(commitments[:], rowIndices, columnIndices, cells, cellProofs)
				require.NoError(b, err)
				require.True(b, ok)
			}
		})
	}
}
