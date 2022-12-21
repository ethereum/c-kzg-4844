package types

const BlobSize = 131072
const CommitmentSize = 144
const ProofSize = 144
const BytesPerFieldElement = 32
const G1Size = 144
const G2Size = 288

type CKzgRet uint
type Blob [BlobSize]byte
type Commitment [CommitmentSize]byte
type Proof [ProofSize]byte
type FieldElement [BytesPerFieldElement]byte
type G1 [G1Size]byte
type G2 [G2Size]byte
