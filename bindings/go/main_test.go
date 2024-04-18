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
	computeCellsTests            = filepath.Join(testDir, "compute_cells/*/*/*")
	computeCellsAndProofsTests   = filepath.Join(testDir, "compute_cells_and_proofs/*/*/*")
	verifyCellProofTests         = filepath.Join(testDir, "verify_cell_proof/*/*/*")
	verifyCellProofBatchTests    = filepath.Join(testDir, "verify_cell_proof_batch/*/*/*")
	recoverPolynomialTests       = filepath.Join(testDir, "recover_polynomial/*/*/*")
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

func TestComputeCells(t *testing.T) {
	type Test struct {
		Input struct {
			Blob string `yaml:"blob"`
		}
		Output *[]Cell `yaml:"output"`
	}

	tests, err := filepath.Glob(computeCellsTests)
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

			cells, err := ComputeCells(&blob)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, *test.Output, cells[:])
			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestComputeCellsAndProofs(t *testing.T) {
	type Test struct {
		Input struct {
			Blob string `yaml:"blob"`
		}
		Output *[][]string `yaml:"output"`
	}

	tests, err := filepath.Glob(computeCellsAndProofsTests)
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

			cells, proofs, err := ComputeCellsAndProofs(&blob)
			if err == nil {
				require.NotNil(t, test.Output)
				var expectedCells []Cell
				for _, cellStr := range (*test.Output)[0] {
					var cell Cell
					err := cell.UnmarshalText([]byte(cellStr))
					require.NoError(t, err)
					expectedCells = append(expectedCells, cell)
				}
				require.Equal(t, expectedCells, cells[:])
				var expectedProofs []KZGProof
				for _, proofStr := range (*test.Output)[1] {
					var proof Bytes48
					err := proof.UnmarshalText([]byte(proofStr))
					require.NoError(t, err)
					expectedProofs = append(expectedProofs, KZGProof(proof))
				}
				require.Equal(t, expectedProofs, proofs[:])

			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestVerifyCellProof(t *testing.T) {
	type Test struct {
		Input struct {
			Commitment string `yaml:"commitment"`
			CellId     uint64 `yaml:"cell_id"`
			Cell       string `yaml:"cell"`
			Proof      string `yaml:"proof"`
		}
		Output *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyCellProofTests)
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

			cellId := test.Input.CellId

			var cell Cell
			err = cell.UnmarshalText([]byte(test.Input.Cell))
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

			valid, err := VerifyCellProof(commitment, cellId, cell, proof)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, *test.Output, valid)
			} else {
				t.Log(err)
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestVerifyCellProofBatch(t *testing.T) {
	type Test struct {
		Input struct {
			RowCommitments []string `yaml:"row_commitments"`
			RowIndices     []uint64 `yaml:"row_indices"`
			ColumnIndices  []uint64 `yaml:"column_indices"`
			Cells          []string `yaml:"cells"`
			Proofs         []string `yaml:"proofs"`
		}
		Output *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyCellProofBatchTests)
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

			var rowCommitments []Bytes48
			for _, c := range test.Input.RowCommitments {
				var commitment Bytes48
				err = commitment.UnmarshalText([]byte(c))
				if err != nil {
					require.Nil(t, test.Output)
					return
				}
				rowCommitments = append(rowCommitments, commitment)
			}

			rowIndices := test.Input.RowIndices
			columnIndices := test.Input.ColumnIndices

			var cells []Cell
			for _, c := range test.Input.Cells {
				var cell Cell
				err = cell.UnmarshalText([]byte(c))
				if err != nil {
					require.Nil(t, test.Output)
					return
				}
				cells = append(cells, cell)
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

			valid, err := VerifyCellProofBatch(rowCommitments, rowIndices, columnIndices, cells, proofs)
			if err == nil {
				require.NotNil(t, test.Output)
				require.Equal(t, *test.Output, valid)
			} else {
				t.Log(err)
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestRecoverPolynomial(t *testing.T) {
	type Test struct {
		Input struct {
			CellIds []uint64 `yaml:"cell_ids"`
			Cells   []string `yaml:"cells"`
		}
		Output *[]Bytes32 `yaml:"output"`
	}

	tests, err := filepath.Glob(recoverPolynomialTests)
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

			cellIds := test.Input.CellIds

			var cells []Cell
			for _, c := range test.Input.Cells {
				var cell Cell
				err = cell.UnmarshalText([]byte(c))
				if err != nil {
					require.Nil(t, test.Output)
					return
				}
				cells = append(cells, cell)
			}

			recovered, err := RecoverPolynomial(cellIds, cells)
			if err == nil {
				require.NotNil(t, test.Output)
				for i, field := range *test.Output {
					j := i / FieldElementsPerCell
					k := i % FieldElementsPerCell
					require.Equal(t, recovered[j][k], field)
				}
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
