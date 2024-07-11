############################################################
# Convenience wrapper where KzgSettings is a global variable
############################################################

import
  results,
  ./kzg

export
  results,
  kzg

type
  Kzg* = object

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

##############################################################
# Private helpers
##############################################################

var gCtx = KzgCtx(nil)

const
  TrustedSetupNotLoadedErr = "Trusted setup not loaded."
  TrustedSetupAlreadyLoadedErr =
    "Trusted setup is already loaded. Free it before loading a new one."

template setupCtx(body: untyped): untyped =
  if not gCtx.isNil:
    return err(TrustedSetupAlreadyLoadedErr)
  let res = body
  if res.isErr:
    return err(res.error)
  gCtx = res.get
  ok()

template verifyCtx(body: untyped): untyped =
  {.gcsafe.}:
    if gCtx.isNil:
      return err(TrustedSetupNotLoadedErr)
    body

##############################################################
# Public functions
##############################################################

proc loadTrustedSetup*(_: type Kzg,
                       input: File,
                       precompute: Natural): Result[void, string] =
  setupCtx:
    kzg.loadTrustedSetup(input, precompute)

proc loadTrustedSetup*(_: type Kzg,
                       fileName: string,
                       precompute: Natural): Result[void, string] =
  setupCtx:
    kzg.loadTrustedSetup(fileName, precompute)

proc loadTrustedSetup*(_: type Kzg,
                       g1Monomial: openArray[G1Data],
                       g1Lagrange: openArray[G1Data],
                       g2Monomial: openArray[G2Data],
                       precompute: Natural):
                           Result[void, string] =
  setupCtx:
    kzg.loadTrustedSetup(g1Monomial, g1Lagrange, g2Monomial, precompute)

proc loadTrustedSetupFromString*(_: type Kzg,
                                 input: string,
                                 precompute: Natural): Result[void, string] =
  setupCtx:
    kzg.loadTrustedSetupFromString(input, precompute)

proc freeTrustedSetup*(_: type Kzg): Result[void, string] =
  verifyCtx:
    gCtx.freeTrustedSetup()
    gCtx = nil
    ok()

proc toCommitment*(blob: KzgBlob):
                    Result[KzgCommitment, string] {.gcsafe.} =
  verifyCtx:
    gCtx.toCommitment(blob)

proc computeProof*(blob: KzgBlob,
                   z: KzgBytes32): Result[KzgProofAndY, string] {.gcsafe.} =
  verifyCtx:
    gCtx.computeProof(blob, z)

proc computeProof*(blob: KzgBlob,
                   commitmentBytes: KzgBytes48):
                     Result[KzgProof, string] {.gcsafe.} =
  verifyCtx:
    gCtx.computeProof(blob, commitmentBytes)

proc verifyProof*(commitment: KzgBytes48,
                  z: KzgBytes32, # Input Point
                  y: KzgBytes32, # Claimed Value
                  proof: KzgBytes48): Result[bool, string] {.gcsafe.} =
  verifyCtx:
    gCtx.verifyProof(commitment, z, y, proof)

proc verifyProof*(blob: KzgBlob,
                  commitment: KzgBytes48,
                  proof: KzgBytes48): Result[bool, string] {.gcsafe.} =
  verifyCtx:
    gCtx.verifyProof(blob, commitment, proof)

proc verifyProofs*(blobs: openArray[KzgBlob],
                  commitments: openArray[KzgBytes48],
                  proofs: openArray[KzgBytes48]): Result[bool, string] {.gcsafe.} =
  verifyCtx:
    gCtx.verifyProofs(blobs, commitments, proofs)

proc verifyProofs*(commitments: openArray[KzgBytes48],
                   cellIndices: openArray[uint64],
                   cells: openArray[KzgCell],
                   proofs: openArray[KzgBytes48]): Result[bool, string] {.gcsafe.} =
  verifyCtx:
    gCtx.verifyProofs(commitments, cellIndices, cells, proofs)

proc computeCellsAndProofs*(blob: KzgBlob): Result[KzgCellsAndKzgProofs, string] {.gcsafe.} =
  verifyCtx:
    gCtx.computeCellsAndProofs(blob)

proc recoverCellsAndProofs*(cellIndices: openArray[uint64],
                   cells: openArray[KzgCell]): Result[KzgCellsAndKzgProofs, string] {.gcsafe.} =
  verifyCtx:
    gCtx.recoverCellsAndProofs(cellIndices, cells)

##############################################################
# Zero overhead aliases that match the spec
##############################################################

template loadTrustedSetupFile*(T: type Kzg, input: File | string, precompute: Natural): untyped =
  loadTrustedSetup(T, input, precompute)

template blobToKzgCommitment*(blob: KzgBlob): untyped =
  toCommitment(blob)

template computeKzgProof*(blob: KzgBlob, z: KzgBytes32): untyped =
  computeProof(blob, z)

template computeBlobKzgProof*(blob: KzgBlob,
                   commitmentBytes: KzgBytes48): untyped =
  computeProof(blob, commitmentBytes)

template verifyKzgProof*(commitment: KzgBytes48,
                   z: KzgBytes32, # Input Point
                   y: KzgBytes32, # Claimed Value
                   proof: KzgBytes48): untyped =
  verifyProof(commitment, z, y, proof)

template verifyBlobKzgProof*(blob: KzgBlob,
                   commitment: KzgBytes48,
                   proof: KzgBytes48): untyped =
  verifyProof(blob, commitment, proof)

template verifyBlobKzgProofBatch*(blobs: openArray[KzgBlob],
                   commitments: openArray[KzgBytes48],
                   proofs: openArray[KzgBytes48]): untyped =
  verifyProofs(blobs, commitments, proofs)

template computeCellsAndKzgProofs*(blob: KzgBlob): untyped =
  computeCellsAndProofs(blob)

template verifyCellKzgProofBatch*(commitments: openArray[KzgBytes48],
                   cellIndices: openArray[uint64],
                   cells: openArray[KzgCell],
                   proofs: openArray[KzgBytes48]): untyped =
  verifyProofs(commitments, cellIndices, cells, proofs)

template recoverCellsAndKzgProofs*(cellIndices: openArray[uint64],
                   cells: openArray[KzgCell]): untyped =
  recoverCellsAndProofs(cellIndices, cells)

{. pop .}
