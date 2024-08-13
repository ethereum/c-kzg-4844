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
  kzg_abi

const
  TrustedSetupNotLoadedErr* = "Trusted setup is not loaded."
  TrustedSetupAlreadyLoadedErr* = "Trusted setup is already loaded."

type
  KzgCtx = ref object
    val: KzgSettings

  KzgProofAndY* = object
    proof*: KzgProof
    y*: KzgBytes32

  KzgCells* = array[CELLS_PER_EXT_BLOB, KzgCell]
  KzgCellsAndKzgProofs* = object
    cells*: array[CELLS_PER_EXT_BLOB, KzgCell]
    proofs*: array[CELLS_PER_EXT_BLOB, KzgProof]

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

##############################################################
# Global variables
##############################################################

var gCtx = KzgCtx(nil)

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
  if gCtx != nil:
    return err(TrustedSetupAlreadyLoadedErr)
  gCtx = new(KzgCtx)
  let res = load_trusted_setup_file(gCtx.val, input, precompute.csize_t)
  if res != KZG_OK:
    return err($res)
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
  if gCtx != nil:
    return err(TrustedSetupAlreadyLoadedErr)
  if g1MonomialBytes.len == 0 or g1LagrangeBytes.len == 0 or g2MonomialBytes.len == 0:
    return err($KZG_BADARGS)

  gCtx = new(KzgCtx)

  let res = load_trusted_setup(gCtx.val,
      g1MonomialBytes[0].getPtr,
      g1MonomialBytes.len.csize_t,
      g1LagrangeBytes[0].getPtr,
      g1LagrangeBytes.len.csize_t,
      g2MonomialBytes[0].getPtr,
      g2MonomialBytes.len.csize_t,
      precompute.csize_t)
  if res != KZG_OK:
    return err($res)
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
  if gCtx == nil:
    return err(TrustedSetupNotLoadedErr)
  free_trusted_setup(gCtx.val)
  gCtx = nil
  return ok()

proc blobToKzgCommitment*(blob: KzgBlob): Result[KzgCommitment, string] =
  if gCtx == nil:
    return err(TrustedSetupNotLoadedErr)
  var ret: KzgCommitment
  let res = blob_to_kzg_commitment(ret, blob.getPtr, gCtx.val)
  verify(res, ret)

proc computeKzgProof*(blob: KzgBlob,
                   z: KzgBytes32): Result[KzgProofAndY, string] =
  if gCtx == nil:
    return err(TrustedSetupNotLoadedErr)
  var ret: KzgProofAndY
  let res = compute_kzg_proof(
    ret.proof,
    ret.y,
    blob.getPtr,
    z.getPtr,
    gCtx.val)
  verify(res, ret)

proc computeBlobKzgProof*(blob: KzgBlob,
                   commitmentBytes: KzgBytes48): Result[KzgProof, string] =
  if gCtx == nil:
    return err(TrustedSetupNotLoadedErr)
  var proof: KzgProof
  let res = compute_blob_kzg_proof(
    proof,
    blob.getPtr,
    commitmentBytes.getPtr,
    gCtx.val)
  verify(res, proof)

proc verifyKzgProof*(commitment: KzgBytes48,
                  z: KzgBytes32, # Input Point
                  y: KzgBytes32, # Claimed Value
                  proof: KzgBytes48): Result[bool, string] =
  if gCtx == nil:
    return err(TrustedSetupNotLoadedErr)
  var valid: bool
  let res = verify_kzg_proof(
    valid,
    commitment.getPtr,
    z.getPtr,
    y.getPtr,
    proof.getPtr,
    gCtx.val)
  verify(res, valid)

proc verifyBlobKzgProof*(blob: KzgBlob,
                  commitment: KzgBytes48,
                  proof: KzgBytes48): Result[bool, string] =
  if gCtx == nil:
    return err(TrustedSetupNotLoadedErr)
  var valid: bool
  let res = verify_blob_kzg_proof(
    valid,
    blob.getPtr,
    commitment.getPtr,
    proof.getPtr,
    gCtx.val)
  verify(res, valid)

proc verifyBlobKzgProofBatch*(blobs: openArray[KzgBlob],
                  commitments: openArray[KzgBytes48],
                  proofs: openArray[KzgBytes48]): Result[bool, string] =
  if gCtx == nil:
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
    blobs.len.csize_t,
    gCtx.val)
  verify(res, valid)

proc computeCellsAndKzgProofs*(blob: KzgBlob): Result[KzgCellsAndKzgProofs, string] =
  if gCtx == nil:
    return err(TrustedSetupNotLoadedErr)
  var ret: KzgCellsAndKzgProofs
  var cellsPtr: ptr KzgCell = ret.cells[0].getPtr
  var proofsPtr: ptr KzgProof = ret.proofs[0].getPtr
  let res = compute_cells_and_kzg_proofs(
    cellsPtr,
    proofsPtr,
    blob.getPtr,
    gCtx.val)
  verify(res, ret)

proc recoverCellsAndKzgProofs*(cellIndices: openArray[uint64],
                   cells: openArray[KzgCell]): Result[KzgCellsAndKzgProofs, string] =
  if gCtx == nil:
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
    cells.len.csize_t,
    gCtx.val)
  verify(res, ret)

proc verifyCellKzgProofBatch*(commitments: openArray[KzgBytes48],
                   cellIndices: openArray[uint64],
                   cells: openArray[KzgCell],
                   proofs: openArray[KzgBytes48]): Result[bool, string] =
  if gCtx == nil:
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
    cells.len.csize_t,
    gCtx.val)
  verify(res, valid)

{. pop .}
