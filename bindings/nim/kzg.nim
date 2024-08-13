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

type
  KZGCtx* = ref object
    valFreed: bool
    val: KZGSettings

  KZGProofAndY* = object
    proof*: KZGProof
    y*: KZGBytes32

  KZGCells* = array[CELLS_PER_EXT_BLOB, KZGCell]
  KZGCellsAndKZGProofs* = object
    cells*: array[CELLS_PER_EXT_BLOB, KZGCell]
    proofs*: array[CELLS_PER_EXT_BLOB, KZGProof]

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

##############################################################
# Private helpers
##############################################################

proc destroy*(x: KZGCtx) =
  # Prevent Nim GC to call free_trusted_setup
  # if user already done it before.
  # Otherwise, the program will crash with segfault.
  if not x.valFreed:
    free_trusted_setup(x.val)
  x.valFreed = true

proc newKZGCtx(): KZGCtx =
  # Nim finalizer is still broken(v1.6)
  # consider to call destroy directly
  new(result, destroy)

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

proc loadTrustedSetup*(input: File, precompute: Natural): Result[KZGCtx, string] =
  let
    ctx = newKZGCtx()
    res = load_trusted_setup_file(ctx.val, input, precompute.csize_t)
  verify(res, ctx)

proc loadTrustedSetup*(fileName: string, precompute: Natural): Result[KZGCtx, string] =
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
                         Result[KZGCtx, string] =
  if g1MonomialBytes.len == 0 or g1LagrangeBytes.len == 0 or g2MonomialBytes.len == 0:
    return err($KZG_BADARGS)

  let
    ctx = newKZGCtx()
    res = load_trusted_setup(ctx.val,
      g1MonomialBytes[0].getPtr,
      g1MonomialBytes.len.csize_t,
      g1LagrangeBytes[0].getPtr,
      g1LagrangeBytes.len.csize_t,
      g2MonomialBytes[0].getPtr,
      g2MonomialBytes.len.csize_t,
      precompute.csize_t)
  verify(res, ctx)

proc loadTrustedSetupFromString*(input: string, precompute: Natural): Result[KZGCtx, string] =
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

proc toCommitment*(ctx: KZGCtx,
                   blob: KZGBlob):
                     Result[KZGCommitment, string] {.gcsafe.} =
  var ret: KZGCommitment
  let res = blob_to_kzg_commitment(ret, blob.getPtr, ctx.val)
  verify(res, ret)

proc computeProof*(ctx: KZGCtx,
                   blob: KZGBlob,
                   z: KZGBytes32): Result[KZGProofAndY, string] {.gcsafe.} =
  var ret: KZGProofAndY
  let res = compute_kzg_proof(
    ret.proof,
    ret.y,
    blob.getPtr,
    z.getPtr,
    ctx.val)
  verify(res, ret)

proc computeProof*(ctx: KZGCtx,
                   blob: KZGBlob,
                   commitmentBytes: KZGBytes48): Result[KZGProof, string] {.gcsafe.} =
  var proof: KZGProof
  let res = compute_blob_kzg_proof(
    proof,
    blob.getPtr,
    commitmentBytes.getPtr,
    ctx.val)
  verify(res, proof)

proc verifyProof*(ctx: KZGCtx,
                  commitment: KZGBytes48,
                  z: KZGBytes32, # Input Point
                  y: KZGBytes32, # Claimed Value
                  proof: KZGBytes48): Result[bool, string] {.gcsafe.} =
  var valid: bool
  let res = verify_kzg_proof(
    valid,
    commitment.getPtr,
    z.getPtr,
    y.getPtr,
    proof.getPtr,
    ctx.val)
  verify(res, valid)

proc verifyProof*(ctx: KZGCtx,
                  blob: KZGBlob,
                  commitment: KZGBytes48,
                  proof: KZGBytes48): Result[bool, string] {.gcsafe.} =
  var valid: bool
  let res = verify_blob_kzg_proof(
    valid,
    blob.getPtr,
    commitment.getPtr,
    proof.getPtr,
    ctx.val)
  verify(res, valid)

proc verifyProofs*(ctx: KZGCtx,
                  blobs: openArray[KZGBlob],
                  commitments: openArray[KZGBytes48],
                  proofs: openArray[KZGBytes48]): Result[bool, string] {.gcsafe.} =
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
    ctx.val)
  verify(res, valid)

proc computeCellsAndProofs*(ctx: KZGCtx,
                   blob: KZGBlob): Result[KZGCellsAndKZGProofs, string] {.gcsafe.} =
  var ret: KZGCellsAndKZGProofs
  var cellsPtr: ptr KZGCell = ret.cells[0].getPtr
  var proofsPtr: ptr KZGProof = ret.proofs[0].getPtr
  let res = compute_cells_and_kzg_proofs(
    cellsPtr,
    proofsPtr,
    blob.getPtr,
    ctx.val)
  verify(res, ret)

proc recoverCellsAndProofs*(ctx: KZGCtx,
                   cellIndices: openArray[uint64],
                   cells: openArray[KZGCell]): Result[KZGCellsAndKZGProofs, string] {.gcsafe.} =
  if cells.len != cellIndices.len:
    return err($KZG_BADARGS)

  if cells.len == 0:
    return err($KZG_BADARGS)

  var ret: KZGCellsAndKZGProofs
  var recoveredCellsPtr: ptr KZGCell = ret.cells[0].getPtr
  var recoveredProofsPtr: ptr KZGProof = ret.proofs[0].getPtr
  let res = recover_cells_and_kzg_proofs(
    recoveredCellsPtr,
    recoveredProofsPtr,
    cellIndices[0].getPtr,
    cells[0].getPtr,
    cells.len.csize_t,
    ctx.val)
  verify(res, ret)

proc verifyProofs*(ctx: KZGCtx,
                   commitments: openArray[KZGBytes48],
                   cellIndices: openArray[uint64],
                   cells: openArray[KZGCell],
                   proofs: openArray[KZGBytes48]): Result[bool, string] {.gcsafe.} =
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
    ctx.val)
  verify(res, valid)

##############################################################
# Zero overhead aliases that match the spec
##############################################################

template loadTrustedSetupFile*(input: File | string, precompute: Natural): untyped =
  loadTrustedSetup(input, precompute)

template freeTrustedSetup*(ctx: KZGCtx) =
  destroy(ctx)

template blobToKZGCommitment*(ctx: KZGCtx,
                   blob: KZGBlob): untyped =
  toCommitment(ctx, blob)

template computeKZGProof*(ctx: KZGCtx,
                   blob: KZGBlob,
                   z: KZGBytes32): untyped =
  computeProof(ctx, blob, z)

template computeBlobKZGProof*(ctx: KZGCtx,
                   blob: KZGBlob,
                   commitmentBytes: KZGBytes48): untyped =
  computeProof(ctx, blob, commitmentBytes)

template verifyKZGProof*(ctx: KZGCtx,
                   commitment: KZGBytes48,
                   z: KZGBytes32, # Input Point
                   y: KZGBytes32, # Claimed Value
                   proof: KZGBytes48): untyped =
  verifyProof(ctx, commitment, z, y, proof)

template verifyBlobKZGProof*(ctx: KZGCtx,
                   blob: KZGBlob,
                   commitment: KZGBytes48,
                   proof: KZGBytes48): untyped =
  verifyProof(ctx, blob, commitment, proof)

template verifyBlobKZGProofBatch*(ctx: KZGCtx,
                   blobs: openArray[KZGBlob],
                   commitments: openArray[KZGBytes48],
                   proofs: openArray[KZGBytes48]): untyped =
  verifyProofs(ctx, blobs, commitments, proofs)

template computeCellsAndKZGProofs*(ctx: KZGCtx,
                   blob: KZGBlob): untyped =
  computeCellsAndProofs(ctx, blob)

template recoverCellsAndKZGProofs*(ctx: KZGCtx,
                   cellIndices: openArray[uint64],
                   cells: openArray[KZGCell]): untyped =
  recoverCellsAndProofs(ctx, cellIndices, cells)

template verifyCellKZGProofBatch*(ctx: KZGCtx,
                   commitments: openArray[KZGBytes48],
                   cellIndices: openArray[uint64],
                   cells: openArray[KZGCell],
                   proofs: openArray[KZGBytes48]): untyped =
  verifyProofs(ctx, commitments, cellIndices, cells, proofs)

{. pop .}
