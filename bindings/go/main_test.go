package ckzg4844

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestMain(m *testing.M) {

	if err := LoadTrustedSetupFile("../../src/trusted_setup.txt", 0); err != nil {
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

func getPartialCells(cells [CellsPerExtBlob]Cell, i int) ([]uint64, []Cell) {
	cellIndices := []uint64{}
	partialCells := []Cell{}
	for j := range cells {
		if j%i != 0 {
			cellIndices = append(cellIndices, uint64(j))
			partialCells = append(partialCells, cells[j])
		}
	}
	return cellIndices, partialCells
}

func getColumns(blobCommitments []Bytes48, cellRows [][CellsPerExtBlob]Cell, proofRows [][CellsPerExtBlob]Bytes48, numCols int) ([]Bytes48, []uint64, []Cell, []Bytes48) {
	var cellCommitments []Bytes48
	var cellIndices []uint64
	var cells []Cell
	var cellProofs []Bytes48
	for i := range cellRows {
		for j := 0; j < numCols; j++ {
			cellCommitments = append(cellCommitments, blobCommitments[i])
			cellIndices = append(cellIndices, uint64(j))
			cells = append(cells, cellRows[i][j])
			cellProofs = append(cellProofs, proofRows[i][j])
		}
	}
	return cellCommitments, cellIndices, cells, cellProofs
}

func divideRoundUp(a, b int) int {
	if b == 0 {
		panic("division by zero")
	}
	return (a + b - 1) / b
}

///////////////////////////////////////////////////////////////////////////////
// Reference Tests
///////////////////////////////////////////////////////////////////////////////

var (
	testDir                       = "../../tests"
	blobToKZGCommitmentTests      = filepath.Join(testDir, "blob_to_kzg_commitment/*/*/*")
	computeKZGProofTests          = filepath.Join(testDir, "compute_kzg_proof/*/*/*")
	computeBlobKZGProofTests      = filepath.Join(testDir, "compute_blob_kzg_proof/*/*/*")
	verifyKZGProofTests           = filepath.Join(testDir, "verify_kzg_proof/*/*/*")
	verifyBlobKZGProofTests       = filepath.Join(testDir, "verify_blob_kzg_proof/*/*/*")
	verifyBlobKZGProofBatchTests  = filepath.Join(testDir, "verify_blob_kzg_proof_batch/*/*/*")
	computeCellsTests             = filepath.Join(testDir, "compute_cells/*/*/*")
	computeCellsAndKZGProofsTests = filepath.Join(testDir, "compute_cells_and_kzg_proofs/*/*/*")
	recoverCellsAndKZGProofsTests = filepath.Join(testDir, "recover_cells_and_kzg_proofs/*/*/*")
	verifyCellKZGProofBatchTests  = filepath.Join(testDir, "verify_cell_kzg_proof_batch/*/*/*")
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
		Output *[]string `yaml:"output"`
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
				var expectedCells []Cell
				for _, cellStr := range *test.Output {
					var cell Cell
					err := cell.UnmarshalText([]byte(cellStr))
					require.NoError(t, err)
					expectedCells = append(expectedCells, cell)
				}
				require.Equal(t, expectedCells, cells[:])

			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestComputeCellsAndKZGProofs(t *testing.T) {
	type Test struct {
		Input struct {
			Blob string `yaml:"blob"`
		}
		Output *[][]string `yaml:"output"`
	}

	tests, err := filepath.Glob(computeCellsAndKZGProofsTests)
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

			cells, proofs, err := ComputeCellsAndKZGProofs(&blob)
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

func TestVerifyCellKZGProofBatch(t *testing.T) {
	type Test struct {
		Input struct {
			Commitments []string `yaml:"commitments"`
			CellIndices []uint64 `yaml:"cell_indices"`
			Cells       []string `yaml:"cells"`
			Proofs      []string `yaml:"proofs"`
		}
		Output *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyCellKZGProofBatchTests)
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

			cellIndices := test.Input.CellIndices

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

			valid, err := VerifyCellKZGProofBatch(commitments, cellIndices, cells, proofs)
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

func TestRecoverCellsAndKZGProofs(t *testing.T) {
	type Test struct {
		Input struct {
			CellIndices []uint64 `yaml:"cell_indices"`
			Cells       []string `yaml:"cells"`
		}
		Output *[][]string `yaml:"output"`
	}

	tests, err := filepath.Glob(recoverCellsAndKZGProofsTests)
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

			cellIndices := test.Input.CellIndices

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

			recoveredCells, recoveredProofs, err := RecoverCellsAndKZGProofs(cellIndices, cells)
			if err == nil {
				require.NotNil(t, test.Output)
				var expectedCells []Cell
				for _, cellStr := range (*test.Output)[0] {
					var cell Cell
					err := cell.UnmarshalText([]byte(cellStr))
					require.NoError(t, err)
					expectedCells = append(expectedCells, cell)
				}
				require.Equal(t, expectedCells, recoveredCells[:])
				var expectedProofs []KZGProof
				for _, proofStr := range (*test.Output)[1] {
					var proof Bytes48
					err := proof.UnmarshalText([]byte(proofStr))
					require.NoError(t, err)
					expectedProofs = append(expectedProofs, KZGProof(proof))
				}
				require.Equal(t, expectedProofs, recoveredProofs[:])

			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestPartialRecover(t *testing.T) {
	var blob Blob
	fillBlobRandom(&blob, 27)
	cells, proofs, err := ComputeCellsAndKZGProofs(&blob)
	require.NoError(t, err)

	for i := 1; i <= 5; i++ {
		mod := divideRoundUp(CellsPerExtBlob, i)
		cellIndices, partialCells := getPartialCells(cells, mod)
		recoveredCells, recoveredProofs, err := RecoverCellsAndKZGProofs(cellIndices, partialCells)
		require.NoError(t, err)
		require.EqualValues(t, cells, recoveredCells)
		require.EqualValues(t, proofs, recoveredProofs)
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
	blobCells := [length][CellsPerExtBlob]Cell{}
	blobCellProofs := [length][CellsPerExtBlob]Bytes48{}

	for i := 0; i < length; i++ {
		var blob Blob
		fillBlobRandom(&blob, int64(i))
		blobs[i] = blob
		commitment, err := BlobToKZGCommitment(&blob)
		commitments[i] = Bytes48(commitment)
		require.NoError(b, err)
		proof, err := ComputeBlobKZGProof(&blob, Bytes48(commitment))
		require.NoError(b, err)
		proofs[i] = Bytes48(proof)

		tProofs := [CellsPerExtBlob]KZGProof{}
		blobCells[i], tProofs, err = ComputeCellsAndKZGProofs(&blobs[i])
		require.NoError(b, err)
		blobCellProofs[i] = [CellsPerExtBlob]Bytes48{}
		for j, p := range tProofs {
			blobCellProofs[i][j] = Bytes48(p)
		}
	}

	FreeTrustedSetup()
	for i := 0; i <= 8; i++ {
		b.Run(fmt.Sprintf("LoadTrustedSetupFile(precompute=%d)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				b.StartTimer()
				err := LoadTrustedSetupFile("../../src/trusted_setup.txt", uint(i))
				b.StopTimer()
				require.NoError(b, err)
				FreeTrustedSetup()
			}
		})
	}

	/* Reload the trusted setup */
	if err := LoadTrustedSetupFile("../../src/trusted_setup.txt", 8); err != nil {
		panic(fmt.Sprintf("failed to load trusted setup: %v", err))
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

	FreeTrustedSetup()
	for i := 0; i <= 8; i++ {
		if err := LoadTrustedSetupFile("../../src/trusted_setup.txt", uint(i)); err != nil {
			panic(fmt.Sprintf("failed to load trusted setup: %v", err))
		}
		b.Run(fmt.Sprintf("ComputeCellsAndKZGProofs(precompute=%d)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, _, err := ComputeCellsAndKZGProofs(&blobs[0])
				require.NoError(b, err)
			}
		})
		FreeTrustedSetup()
	}

	/* Reload the trusted setup */
	if err := LoadTrustedSetupFile("../../src/trusted_setup.txt", 8); err != nil {
		panic(fmt.Sprintf("failed to load trusted setup: %v", err))
	}

	count := runtime.NumCPU()
	if count > length {
		count = length
	}
	b.Run(fmt.Sprintf("ComputeCellsAndKZGProofsParallel(count=%v)", count), func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			var wg sync.WaitGroup
			for i := 0; i < count; i++ {
				wg.Add(1)
				go func(x *Blob) {
					defer wg.Done()
					_, _, err := ComputeCellsAndKZGProofs(x)
					require.NoError(b, err)
				}(&blobs[i])
			}
			wg.Wait()
		}
	})

	for i := 2; i <= 8; i *= 2 {
		percentMissing := (1.0 / float64(i)) * 100
		cellIndices, partialCells := getPartialCells(blobCells[0], i)
		b.Run(fmt.Sprintf("RecoverCellsAndKZGProofs(missing=%2.1f%%)", percentMissing), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, _, err := RecoverCellsAndKZGProofs(cellIndices, partialCells)
				require.NoError(b, err)
			}
		})
	}

	for i := 1; i <= 5; i++ {
		mod := divideRoundUp(CellsPerExtBlob, i)
		cellIndices, partialCells := getPartialCells(blobCells[0], mod)
		b.Run(fmt.Sprintf("RecoverCellsAndKZGProofs(missing=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, _, err := RecoverCellsAndKZGProofs(cellIndices, partialCells)
				require.NoError(b, err)
			}
		})
	}

	b.Run("VerifyCellKZGProofBatch", func(b *testing.B) {
		var cellCommitments []Bytes48
		var cellIndices []uint64
		var cells []Cell
		var cellProofs []Bytes48
		for rowIndex, blobCell := range blobCells {
			for cellIndex, cell := range blobCell {
				cellCommitments = append(cellCommitments, commitments[rowIndex])
				cellIndices = append(cellIndices, uint64(cellIndex))
				cells = append(cells, cell)
				cellProofs = append(cellProofs, blobCellProofs[rowIndex][cellIndex])
			}
		}
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			ok, err := VerifyCellKZGProofBatch(cellCommitments, cellIndices, cells, cellProofs)
			require.NoError(b, err)
			require.True(b, ok)
		}
	})

	b.Run("VerifyCellKZGProofBatchParallel", func(b *testing.B) {
		// Determine the ideal group count
		numGroups := runtime.NumCPU()
		if numGroups > length {
			numGroups = length
		}
		// Decrementing until each group has equal blobs
		for numGroups > 0 && length%numGroups != 0 {
			numGroups--
		}
		blobsPerGroup := length / numGroups

		// Pre-partition the cell data into groups
		type groupData struct {
			cellCommitments []Bytes48
			cellIndices     []uint64
			cells           []Cell
			cellProofs      []Bytes48
		}
		groups := make([]groupData, numGroups)
		for group := 0; group < numGroups; group++ {
			startBlob := group * blobsPerGroup
			endBlob := startBlob + blobsPerGroup

			var groupCommitments []Bytes48
			var groupIndices []uint64
			var groupCells []Cell
			var groupProofs []Bytes48

			for blobIndex := startBlob; blobIndex < endBlob; blobIndex++ {
				for cellIndex, cell := range blobCells[blobIndex] {
					groupCommitments = append(groupCommitments, commitments[blobIndex])
					groupIndices = append(groupIndices, uint64(cellIndex))
					groupCells = append(groupCells, cell)
					groupProofs = append(groupProofs, blobCellProofs[blobIndex][cellIndex])
				}
			}
			groups[group] = groupData{
				cellCommitments: groupCommitments,
				cellIndices:     groupIndices,
				cells:           groupCells,
				cellProofs:      groupProofs,
			}
		}

		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			var wg sync.WaitGroup
			for group := 0; group < numGroups; group++ {
				wg.Add(1)
				go func(group int) {
					defer wg.Done()
					ok, err := VerifyCellKZGProofBatch(
						groups[group].cellCommitments,
						groups[group].cellIndices,
						groups[group].cells,
						groups[group].cellProofs,
					)
					require.NoError(b, err)
					require.True(b, ok)
				}(group)
			}
			wg.Wait()
		}
	})

	for i := 1; i <= length; i *= 2 {
		b.Run(fmt.Sprintf("VerifyRows(count=%v)", i), func(b *testing.B) {
			var cellCommitments []Bytes48
			var cellIndices []uint64
			var cells []Cell
			var cellProofs []Bytes48
			for rowIndex, blobCell := range blobCells {
				if rowIndex == i {
					break
				}
				for cellIndex, cell := range blobCell {
					cellCommitments = append(cellCommitments, commitments[rowIndex])
					cellIndices = append(cellIndices, uint64(cellIndex))
					cells = append(cells, cell)
					cellProofs = append(cellProofs, blobCellProofs[rowIndex][cellIndex])
				}
			}
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				ok, err := VerifyCellKZGProofBatch(cellCommitments, cellIndices, cells, cellProofs)
				require.NoError(b, err)
				require.True(b, ok)
			}
		})
	}

	for i := 1; i <= CellsPerExtBlob; i *= 2 {
		cellCommitments, cellIndices, cells, cellProofs := getColumns(commitments[:], blobCells[:], blobCellProofs[:], i)
		b.Run(fmt.Sprintf("VerifyColumns(count=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				ok, err := VerifyCellKZGProofBatch(cellCommitments, cellIndices, cells, cellProofs)
				require.NoError(b, err)
				require.True(b, ok)
			}
		})
	}
}
