package ckzg4844

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	blst "github.com/supranational/blst/bindings/go"
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
	var blob Blob
	for i := 0; i < BytesPerBlob; i += BytesPerFieldElement {
		fieldElementBytes := getRandFieldElement(seed + int64(i))
		copy(blob[i:i+BytesPerFieldElement], fieldElementBytes[:])
	}
	return blob
}

func getRandPoint(seed int64) Bytes48 {
	var ikm [32]byte
	binary.BigEndian.PutUint64(ikm[0:8], uint64(seed))
	sk := blst.KeyGen(ikm[:])
	pk := new(blst.P1Affine).From(sk).Compress()
	bytes := Bytes48{}
	copy(bytes[:], pk)
	return bytes
}

func deleteSamples(samples BlobSamples, i int) BlobSamples {
	var partialSamples BlobSamples
	for j := 0; j < SamplesPerBlob; j++ {
		if j%i == 0 {
			partialSamples[j] = NullSample
		} else {
			partialSamples[j] = samples[j]
		}
	}
	return partialSamples
}

func getPartialSamples(samples SampleTable) SampleTable {
	type Pair[T, U any] struct {
		First  T
		Second U
	}

	var partialSamples SampleTable
	indices := make([]Pair[int, int], SamplesPerBlob*SamplesPerBlob)
	for i := 0; i < 2*BlobCount; i++ {
		for j := 0; j < SamplesPerBlob; j++ {
			indices[i*SamplesPerBlob+j] = Pair[int, int]{i, j}
			partialSamples[i][j] = samples[i][j]
		}
	}

	/* Mark the first 25% of shuffled indices as missing */
	rand.Shuffle(len(indices), func(i, j int) { indices[i], indices[j] = indices[j], indices[i] })
	count := len(indices) / 4
	for _, index := range indices[:count] {
		partialSamples[index.First][index.Second] = NullSample
	}

	return partialSamples
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

func TestSampleProof(t *testing.T) {
	blob := getRandBlob(0)

	commitment, err := BlobToKZGCommitment(blob)
	require.NoError(t, err)
	samples, proofs, err := GetSamplesAndProofs(blob)
	require.NoError(t, err)

	for i := range proofs[:] {
		ok, err := VerifySampleProof(Bytes48(commitment), Bytes48(proofs[i]), samples[i], i)
		require.NoError(t, err)
		require.True(t, ok)
	}
}

func Test2dRecover(t *testing.T) {
	/* Generate some random blobs */
	var blobs [BlobCount]Blob
	for i := range blobs {
		blobs[i] = getRandBlob(int64(i))
	}

	/* Get a 2d array of samples for the blobs */
	samples, proofs, err := Get2dSamplesAndProofs(blobs)
	require.NoError(t, err)

	/* Mark 25% of them as missing */
	partialSamples := getPartialSamples(samples)

	/* Recover data */
	recovered, err := Recover2dSamples(partialSamples)
	require.NoError(t, err)

	/* Ensure recovered matches original */
	require.Equal(t, len(samples), len(recovered))
	var wg sync.WaitGroup
	for i := range samples {
		wg.Add(1)
		go func(x int) {
			defer wg.Done()
			require.Equal(t, len(samples[x]), len(recovered[x]))
			blob, err := SamplesToBlob(samples[x])
			require.NoError(t, err)
			commitment, err := BlobToKZGCommitment(blob)
			require.NoError(t, err)
			for j := range samples[x] {
				require.Equal(t, samples[x][j], recovered[x][j])
				ok, err := VerifySampleProof(Bytes48(commitment), Bytes48(proofs[x][j]), samples[x][j], j)
				require.NoError(t, err)
				require.True(t, ok)
			}
		}(i)
	}
	wg.Wait()
}

func Test2dRecoverFirstRowIsMissing(t *testing.T) {
	/* Generate some random blobs */
	var blobs [BlobCount]Blob
	for i := range blobs {
		blobs[i] = getRandBlob(int64(i))
	}

	/* Get a 2d array of samples for the blobs */
	samples, proofs, err := Get2dSamplesAndProofs(blobs)
	require.NoError(t, err)

	/* Copy samples so we mark some as missing */
	var partialSamples SampleTable
	for i := range samples {
		copy(partialSamples[i][:], samples[i][:])
	}

	/* Mark the first 75% samples in the first row as null */
	l := (len(partialSamples[0]) / 4) * 3
	for j := range partialSamples[0][:l] {
		partialSamples[0][j] = NullSample
	}

	/* Recover data */
	recovered, err := Recover2dSamples(partialSamples)
	require.NoError(t, err)

	/* Ensure recovered matches original */
	require.Equal(t, len(samples), len(recovered))
	var wg sync.WaitGroup
	for i := range samples {
		wg.Add(1)
		go func(x int) {
			defer wg.Done()
			require.Equal(t, len(samples[x]), len(recovered[x]))
			blob, err := SamplesToBlob(samples[x])
			require.NoError(t, err)
			commitment, err := BlobToKZGCommitment(blob)
			require.NoError(t, err)
			for j := range samples[x] {
				require.Equal(t, samples[x][j], recovered[x][j])
				ok, err := VerifySampleProof(Bytes48(commitment), Bytes48(proofs[x][j]), samples[x][j], j)
				require.NoError(t, err)
				require.True(t, ok)
			}
		}(i)
	}
	wg.Wait()
}

func TestRecoverNoMissing(t *testing.T) {
	blob := getRandBlob(0)
	samples, _, err := GetSamplesAndProofs(blob)
	require.NoError(t, err)
	recovered, err := RecoverSamples(samples)
	require.NoError(t, err)
	require.Equal(t, recovered, samples)
}

///////////////////////////////////////////////////////////////////////////////
// Benchmarks
///////////////////////////////////////////////////////////////////////////////

func Benchmark(b *testing.B) {
	blobs := [BlobCount]Blob{}
	commitments := [BlobCount]Bytes48{}
	proofs := [BlobCount]Bytes48{}
	fields := [BlobCount]Bytes32{}
	samples := [BlobCount]BlobSamples{}
	sampleProofs := [BlobCount]BlobSampleProofs{}
	sampleTable := SampleTable{}
	partialSampleTable := SampleTable{}

	randBlob := getRandBlob(0)
	randCommitment := getRandPoint(0)
	randProof := getRandPoint(0)
	randField := getRandFieldElement(0)
	var randSample Sample
	for i := range randSample {
		randSample[i] = randField
	}

	for i := 0; i < BlobCount; i++ {
		blobs[i] = randBlob
		commitments[i] = randCommitment
		proofs[i] = randProof
		fields[i] = randField
		for j := 0; j < SamplesPerBlob; j++ {
			sampleProofs[i][j] = KZGProof(randProof)
			samples[i][j] = randSample
		}
	}

	for j := 0; j < SamplesPerBlob; j++ {
		for k := 0; k < SamplesPerBlob; k++ {
			sampleTable[j][k] = randSample
		}
	}
	partialSampleTable = getPartialSamples(sampleTable)

	b.Run("BlobToKZGCommitment", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := BlobToKZGCommitment(blobs[0])
			require.Nil(b, err)
		}
	})

	b.Run("ComputeKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _, err := ComputeKZGProof(blobs[0], fields[0])
			require.Nil(b, err)
		}
	})

	b.Run("ComputeBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := ComputeBlobKZGProof(blobs[0], commitments[0])
			require.Nil(b, err)
		}
	})

	b.Run("VerifyKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := VerifyKZGProof(commitments[0], fields[0], fields[1], proofs[0])
			require.Nil(b, err)
		}
	})

	b.Run("VerifyBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := VerifyBlobKZGProof(blobs[0], commitments[0], proofs[0])
			require.Nil(b, err)
		}
	})

	for i := 1; i <= len(blobs); i *= 2 {
		b.Run(fmt.Sprintf("VerifyBlobKZGProofBatch(count=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, err := VerifyBlobKZGProofBatch(blobs[:i], commitments[:i], proofs[:i])
				require.Nil(b, err)
			}
		})
	}

	b.Run("GetSamplesAndProofs", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _, err := GetSamplesAndProofs(blobs[0])
			require.Nil(b, err)
		}
	})

	b.Run("SamplesToBlob", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := SamplesToBlob(samples[0])
			require.Nil(b, err)
		}
	})

	for i := 2; i <= 8; i *= 2 {
		percentMissing := (1.0 / float64(i)) * 100
		partial := deleteSamples(samples[0], i)
		b.Run(fmt.Sprintf("RecoverSamples(missing=%2.1f%%)", percentMissing), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, err := RecoverSamples(partial)
				require.Nil(b, err)
			}
		})
	}

	b.Run("VerifySampleProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := VerifySampleProof(commitments[0], Bytes48(sampleProofs[0][0]), samples[0][0], 0)
			require.Nil(b, err)
		}
	})

	b.Run("Recover2dSamples", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := Recover2dSamples(partialSampleTable)
			require.Nil(b, err)
		}
	})

	b.Run("Get2dSamplesAndProofs", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _, err := Get2dSamplesAndProofs(blobs)
			require.Nil(b, err)
		}
	})
}
