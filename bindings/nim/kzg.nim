############################################################
# Main API, wrapper on top of C FFI
############################################################

import
  std/[streams, strutils],
  stew/[assign2, byteutils],
  results,
  ./kzg_abi

export
  results,
  kzg_abi.KzgBlob,
  kzg_abi.KzgBytes32,
  kzg_abi.KzgBytes48,
  kzg_abi.KzgCell,
  kzg_abi.KzgCommitment,
  kzg_abi.KzgProof

const
  TrustedSetupNotLoadedErr* = "Trusted setup is not loaded."
  TrustedSetupAlreadyLoadedErr* = "Trusted setup is already loaded."

type
  KzgCtx = object
    initialized: bool
    settings: KzgSettings

  KzgProofAndY* = object
    proof*: KzgProof
    y*: KzgBytes32

  KzgCells* = array[CELLS_PER_EXT_BLOB, KzgCell]
  KzgCellsAndKzgProofs* = object
    cells*: array[CELLS_PER_EXT_BLOB, KzgCell]
    proofs*: array[CELLS_PER_EXT_BLOB, KzgProof]

{.push raises: [], gcsafe.}

##############################################################
# Global variables
##############################################################

var gCtx: KzgCtx

##############################################################
# Private helpers
##############################################################

template getPtr(x: untyped): auto =
  when (NimMajor, NimMinor) <= (1,6):
    unsafeAddr(x)
  else:
    addr(x)

template verify(res: KZG_RET, ret: untyped): untyped =
  if res != KZG_OK:
    return err($res)
  ok(ret)

##############################################################
# Public functions
##############################################################

proc loadTrustedSetup*(input: File, precompute: Natural): Result[void, string] =
  if gCtx.initialized:
    return err(TrustedSetupAlreadyLoadedErr)
  let res = load_trusted_setup_file(addr(gCtx.settings), input, precompute.uint64)
  if res != KZG_OK:
    gCtx.settings.reset()
    return err($res)
  gCtx.initialized = true
  return ok()

proc loadTrustedSetup*(fileName: string, precompute: Natural): Result[void, string] =
  try:
    let file = open(fileName)
    result = file.loadTrustedSetup(precompute)
    file.close()
  except IOError as ex:
    return err(ex.msg)

proc loadTrustedSetup*(g1MonomialBytes: openArray[byte],
                       g1LagrangeBytes: openArray[byte],
                       g2MonomialBytes: openArray[byte],
                       precompute: Natural):
                         Result[void, string] =
  if gCtx.initialized:
    return err(TrustedSetupAlreadyLoadedErr)
  if g1MonomialBytes.len == 0 or g1LagrangeBytes.len == 0 or g2MonomialBytes.len == 0:
    return err($KZG_BADARGS)

  let res = load_trusted_setup(
      addr(gCtx.settings),
      g1MonomialBytes[0].getPtr,
      g1MonomialBytes.len.uint64,
      g1LagrangeBytes[0].getPtr,
      g1LagrangeBytes.len.uint64,
      g2MonomialBytes[0].getPtr,
      g2MonomialBytes.len.uint64,
      precompute.uint64)
  if res != KZG_OK:
    return err($res)
  gCtx.initialized = true
  return ok()

proc loadTrustedSetupFromString*(input: string, precompute: Natural): Result[void, string] =
  const
    NumG1 = FIELD_ELEMENTS_PER_BLOB
    NumG2 = 65
    G1Len = 48
    G2Len = 96

  var
    s = newStringStream(input)
    g1MonomialBytes: array[NumG1 * G1Len, byte]
    g1LagrangeBytes: array[NumG1 * G1Len, byte]
    g2MonomialBytes: array[NumG2 * G2Len, byte]

  try:
    let numG1 = s.readLine().parseInt()
    if numG1 != NumG1:
      return err("invalid number of G1 points, expect $1, got $2" % [
        $NumG1, $numG1
      ])
    let numG2 = s.readLine().parseInt()
    if numG2 != NumG2:
      return err("invalid number of G2 points, expect $1, got $2" % [
        $NumG2, $numG2
      ])

    for i in 0 ..< NumG1:
      let p = hexToByteArray[G1Len](s.readLine())
      assign(g1LagrangeBytes.toOpenArray(i * G1Len, ((i + 1) * G1Len) - 1), p)

    for i in 0 ..< NumG2:
      let p = hexToByteArray[G2Len](s.readLine())
      assign(g2MonomialBytes.toOpenArray(i * G2Len, ((i + 1) * G2Len) - 1), p)

    for i in 0 ..< NumG1:
      let p = hexToByteArray[G1Len](s.readLine())
      assign(g1MonomialBytes.toOpenArray(i * G1Len, ((i + 1) * G1Len) - 1), p)

  except ValueError as ex:
    return err(ex.msg)
  except OSError as ex:
    return err(ex.msg)
  except IOError as ex:
    return err(ex.msg)

  loadTrustedSetup(g1MonomialBytes, g1LagrangeBytes, g2MonomialBytes, precompute)

proc freeTrustedSetup*(): Result[void, string] =
  if not gCtx.initialized:
    return err(TrustedSetupNotLoadedErr)
  gCtx.initialized = false
  free_trusted_setup(addr(gCtx.settings))
  gCtx.settings.reset()
  return ok()

proc blobToKzgCommitment*(blob: KzgBlob): Result[KzgCommitment, string] =
  if not gCtx.initialized:
    return err(TrustedSetupNotLoadedErr)
  var ret: KzgCommitment
  let res = blob_to_kzg_commitment(ret, blob.getPtr, addr(gCtx.settings))
  verify(res, ret)

proc computeKzgProof*(blob: KzgBlob,
                   z: KzgBytes32): Result[KzgProofAndY, string] =
  if not gCtx.initialized:
    return err(TrustedSetupNotLoadedErr)
  var ret: KzgProofAndY
  let res = compute_kzg_proof(
    ret.proof,
    ret.y,
    blob.getPtr,
    z.getPtr,
    addr(gCtx.settings))
  verify(res, ret)

proc computeBlobKzgProof*(blob: KzgBlob,
                   commitmentBytes: KzgBytes48): Result[KzgProof, string] =
  if not gCtx.initialized:
    return err(TrustedSetupNotLoadedErr)
  var proof: KzgProof
  let res = compute_blob_kzg_proof(
    proof,
    blob.getPtr,
    commitmentBytes.getPtr,
    addr(gCtx.settings))
  verify(res, proof)

proc verifyKzgProof*(commitment: KzgBytes48,
                  z: KzgBytes32, # Input Point
                  y: KzgBytes32, # Claimed Value
                  proof: KzgBytes48): Result[bool, string] =
  if not gCtx.initialized:
    return err(TrustedSetupNotLoadedErr)
  var valid: bool
  let res = verify_kzg_proof(
    valid,
    commitment.getPtr,
    z.getPtr,
    y.getPtr,
    proof.getPtr,
    addr(gCtx.settings))
  verify(res, valid)

proc verifyBlobKzgProof*(blob: KzgBlob,
                  commitment: KzgBytes48,
                  proof: KzgBytes48): Result[bool, string] =
  if not gCtx.initialized:
    return err(TrustedSetupNotLoadedErr)
  var valid: bool
  let res = verify_blob_kzg_proof(
    valid,
    blob.getPtr,
    commitment.getPtr,
    proof.getPtr,
    addr(gCtx.settings))
  verify(res, valid)

proc verifyBlobKzgProofBatch*(blobs: openArray[KzgBlob],
                  commitments: openArray[KzgBytes48],
                  proofs: openArray[KzgBytes48]): Result[bool, string] =
  if not gCtx.initialized:
    return err(TrustedSetupNotLoadedErr)
  if blobs.len != commitments.len:
    return err($KZG_BADARGS)
  if blobs.len != proofs.len:
    return err($KZG_BADARGS)
  if blobs.len == 0:
    return ok(true)

  var valid: bool
  let res = verify_blob_kzg_proof_batch(
    valid,
    blobs[0].getPtr,
    commitments[0].getPtr,
    proofs[0].getPtr,
    blobs.len.uint64,
    addr(gCtx.settings))
  verify(res, valid)

proc computeCells*(blob: KzgBlob): Result[KzgCells, string] =
  if not gCtx.initialized:
    return err(TrustedSetupNotLoadedErr)
  var ret: KzgCells
  var cellsPtr: ptr KzgCell = ret[0].getPtr
  let res = compute_cells_and_kzg_proofs(
    cellsPtr,
    nil,
    blob.getPtr,
    addr(gCtx.settings))
  verify(res, ret)

proc computeCellsAndKzgProofs*(blob: KzgBlob): Result[KzgCellsAndKzgProofs, string] =
  if not gCtx.initialized:
    return err(TrustedSetupNotLoadedErr)
  var ret: KzgCellsAndKzgProofs
  var cellsPtr: ptr KzgCell = ret.cells[0].getPtr
  var proofsPtr: ptr KzgProof = ret.proofs[0].getPtr
  let res = compute_cells_and_kzg_proofs(
    cellsPtr,
    proofsPtr,
    blob.getPtr,
    addr(gCtx.settings))
  verify(res, ret)

proc recoverCellsAndKzgProofs*(cellIndices: openArray[uint64],
                   cells: openArray[KzgCell]): Result[KzgCellsAndKzgProofs, string] =
  if not gCtx.initialized:
    return err(TrustedSetupNotLoadedErr)
  if cells.len != cellIndices.len:
    return err($KZG_BADARGS)
  if cells.len == 0:
    return err($KZG_BADARGS)

  var ret: KzgCellsAndKzgProofs
  var recoveredCellsPtr: ptr KzgCell = ret.cells[0].getPtr
  var recoveredProofsPtr: ptr KzgProof = ret.proofs[0].getPtr
  let res = recover_cells_and_kzg_proofs(
    recoveredCellsPtr,
    recoveredProofsPtr,
    cellIndices[0].getPtr,
    cells[0].getPtr,
    cells.len.uint64,
    addr(gCtx.settings))
  verify(res, ret)

proc verifyCellKzgProofBatch*(commitments: openArray[KzgBytes48],
                   cellIndices: openArray[uint64],
                   cells: openArray[KzgCell],
                   proofs: openArray[KzgBytes48]): Result[bool, string] =
  if not gCtx.initialized:
    return err(TrustedSetupNotLoadedErr)
  if commitments.len != cells.len:
    return err($KZG_BADARGS)
  if cellIndices.len != cells.len:
    return err($KZG_BADARGS)
  if proofs.len != cells.len:
    return err($KZG_BADARGS)
  if cells.len == 0:
    return ok(true)

  var valid: bool
  let res = verify_cell_kzg_proof_batch(
    valid,
    commitments[0].getPtr,
    cellIndices[0].getPtr,
    cells[0].getPtr,
    proofs[0].getPtr,
    cells.len.uint64,
    addr(gCtx.settings))
  verify(res, valid)

{. pop .}
