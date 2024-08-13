############################################################
# Convenience wrapper where KZGSettings is a global variable
############################################################

import
  results,
  ./kzg

export
  results,
  kzg

type
  KZG* = object

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

##############################################################
# Private helpers
##############################################################

var gCtx = KZGCtx(nil)

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

proc loadTrustedSetup*(_: type KZG,
                       input: File,
                       precompute: Natural): Result[void, string] =
  setupCtx:
    kzg.loadTrustedSetup(input, precompute)

proc loadTrustedSetup*(_: type KZG,
                       fileName: string,
                       precompute: Natural): Result[void, string] =
  setupCtx:
    kzg.loadTrustedSetup(fileName, precompute)

proc loadTrustedSetup*(_: type KZG,
                       g1MonomialBytes: openArray[byte],
                       g1LagrangeBytes: openArray[byte],
                       g2MonomialBytes: openArray[byte],
                       precompute: Natural):
                           Result[void, string] =
  setupCtx:
    kzg.loadTrustedSetup(g1MonomialBytes, g1LagrangeBytes, g2MonomialBytes, precompute)

proc loadTrustedSetupFromString*(_: type KZG,
                                 input: string,
                                 precompute: Natural): Result[void, string] =
  setupCtx:
    kzg.loadTrustedSetupFromString(input, precompute)

proc freeTrustedSetup*(_: type KZG): Result[void, string] =
  verifyCtx:
    gCtx.freeTrustedSetup()
    gCtx = nil
    ok()

proc toCommitment*(blob: KZGBlob):
                    Result[KZGCommitment, string] {.gcsafe.} =
  verifyCtx:
    gCtx.toCommitment(blob)

proc computeProof*(blob: KZGBlob,
                   z: KZGBytes32): Result[KZGProofAndY, string] {.gcsafe.} =
  verifyCtx:
    gCtx.computeProof(blob, z)

proc computeProof*(blob: KZGBlob,
                   commitmentBytes: KZGBytes48):
                     Result[KZGProof, string] {.gcsafe.} =
  verifyCtx:
    gCtx.computeProof(blob, commitmentBytes)

proc verifyProof*(commitment: KZGBytes48,
                  z: KZGBytes32, # Input Point
                  y: KZGBytes32, # Claimed Value
                  proof: KZGBytes48): Result[bool, string] {.gcsafe.} =
  verifyCtx:
    gCtx.verifyProof(commitment, z, y, proof)

proc verifyProof*(blob: KZGBlob,
                  commitment: KZGBytes48,
                  proof: KZGBytes48): Result[bool, string] {.gcsafe.} =
  verifyCtx:
    gCtx.verifyProof(blob, commitment, proof)

proc verifyProofs*(blobs: openArray[KZGBlob],
                  commitments: openArray[KZGBytes48],
                  proofs: openArray[KZGBytes48]): Result[bool, string] {.gcsafe.} =
  verifyCtx:
    gCtx.verifyProofs(blobs, commitments, proofs)

proc computeCellsAndProofs*(blob: KZGBlob): Result[KZGCellsAndKZGProofs, string] {.gcsafe.} =
  verifyCtx:
    gCtx.computeCellsAndProofs(blob)

proc recoverCellsAndProofs*(cellIndices: openArray[uint64],
                   cells: openArray[KZGCell]): Result[KZGCellsAndKZGProofs, string] {.gcsafe.} =
  verifyCtx:
    gCtx.recoverCellsAndProofs(cellIndices, cells)

proc verifyProofs*(commitments: openArray[KZGBytes48],
                   cellIndices: openArray[uint64],
                   cells: openArray[KZGCell],
                   proofs: openArray[KZGBytes48]): Result[bool, string] {.gcsafe.} =
  verifyCtx:
    gCtx.verifyProofs(commitments, cellIndices, cells, proofs)

##############################################################
# Zero overhead aliases that match the spec
##############################################################

template loadTrustedSetupFile*(T: type KZG, input: File | string, precompute: Natural): untyped =
  loadTrustedSetup(T, input, precompute)

template blobToKZGCommitment*(blob: KZGBlob): untyped =
  toCommitment(blob)

template computeKZGProof*(blob: KZGBlob, z: KZGBytes32): untyped =
  computeProof(blob, z)

template computeBlobKZGProof*(blob: KZGBlob,
                   commitmentBytes: KZGBytes48): untyped =
  computeProof(blob, commitmentBytes)

template verifyKZGProof*(commitment: KZGBytes48,
                   z: KZGBytes32, # Input Point
                   y: KZGBytes32, # Claimed Value
                   proof: KZGBytes48): untyped =
  verifyProof(commitment, z, y, proof)

template verifyBlobKZGProof*(blob: KZGBlob,
                   commitment: KZGBytes48,
                   proof: KZGBytes48): untyped =
  verifyProof(blob, commitment, proof)

template verifyBlobKZGProofBatch*(blobs: openArray[KZGBlob],
                   commitments: openArray[KZGBytes48],
                   proofs: openArray[KZGBytes48]): untyped =
  verifyProofs(blobs, commitments, proofs)

template computeCellsAndKZGProofs*(blob: KZGBlob): untyped =
  computeCellsAndProofs(blob)

template recoverCellsAndKZGProofs*(cellIndices: openArray[uint64],
                   cells: openArray[KZGCell]): untyped =
  recoverCellsAndProofs(cellIndices, cells)

template verifyCellKZGProofBatch*(commitments: openArray[KZGBytes48],
                   cellIndices: openArray[uint64],
                   cells: openArray[KZGCell],
                   proofs: openArray[KZGBytes48]): untyped =
  verifyProofs(commitments, cellIndices, cells, proofs)

{. pop .}
