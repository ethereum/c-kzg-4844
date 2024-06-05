############################################################
# Main API, wrapper on top of C FFI
############################################################

import
  std/[streams, strutils],
  stew/byteutils,
  results,
  ./kzg_abi

export
  results,
  kzg_abi

type
  KzgCtx* = ref object
    valFreed: bool
    val: KzgSettings

  KzgProofAndY* = object
    proof*: KzgProof
    y*: KzgBytes32

  KzgCells* = array[CELLS_PER_EXT_BLOB, KzgCell]
  KzgCellsAndKzgProofs* = object
    cells*: array[CELLS_PER_EXT_BLOB, KzgCell]
    proofs*: array[CELLS_PER_EXT_BLOB, KzgProof]

  G1Data* = array[48, byte]
  G2Data* = array[96, byte]

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

##############################################################
# Private helpers
##############################################################

proc destroy*(x: KzgCtx) =
  # Prevent Nim GC to call free_trusted_setup
  # if user already done it before.
  # Otherwise, the program will crash with segfault.
  if not x.valFreed:
    free_trusted_setup(x.val)
  x.valFreed = true

proc newKzgCtx(): KzgCtx =
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

proc loadTrustedSetup*(input: File, precompute: Natural): Result[KzgCtx, string] =
  let
    ctx = newKzgCtx()
    res = load_trusted_setup_file(ctx.val, input, precompute.csize_t)
  verify(res, ctx)

proc loadTrustedSetup*(fileName: string, precompute: Natural): Result[KzgCtx, string] =
  try:
    let file = open(fileName)
    result = file.loadTrustedSetup(precompute)
    file.close()
  except IOError as ex:
    return err(ex.msg)

proc loadTrustedSetup*(g1Monomial: openArray[G1Data],
                       g1Lagrange: openArray[G1Data],
                       g2Monomial: openArray[G2Data],
                       precompute: Natural):
                         Result[KzgCtx, string] =
  if g1Monomial.len == 0 or g1Lagrange.len == 0 or g2Monomial.len == 0:
    return err($KZG_BADARGS)
  if g1Monomial.len != g1Lagrange.len:
    return err($KZG_BADARGS)

  let
    ctx = newKzgCtx()
    res = load_trusted_setup(ctx.val,
      g1Monomial[0][0].getPtr,
      g1Lagrange[0][0].getPtr,
      g1Monomial.len.csize_t,
      g2Monomial[0][0].getPtr,
      g2Monomial.len.csize_t,
      precompute.csize_t)
  verify(res, ctx)

proc loadTrustedSetupFromString*(input: string, precompute: Natural): Result[KzgCtx, string] =
  const
    NumG2 = 65
    G1Len = G1Data.len
    G2Len = G2Data.len

  var
    s = newStringStream(input)
    g1Monomial: array[FIELD_ELEMENTS_PER_BLOB, G1Data]
    g1Lagrange: array[FIELD_ELEMENTS_PER_BLOB, G1Data]
    g2Monomial: array[NumG2, G2Data]

  try:
    let fieldElems = s.readLine().parseInt()
    if fieldElems != FIELD_ELEMENTS_PER_BLOB:
      return err("invalid field elements per blob, expect $1, got $2" % [
        $FIELD_ELEMENTS_PER_BLOB, $fieldElems
      ])
    let numG2 = s.readLine().parseInt()
    if numG2 != NumG2:
      return err("invalid number of G2, expect $1, got $2" % [
        $NumG2, $numG2
      ])

    for i in 0 ..< FIELD_ELEMENTS_PER_BLOB:
      g1Lagrange[i] = hexToByteArray[G1Len](s.readLine())

    for i in 0 ..< NumG2:
      g2Monomial[i] = hexToByteArray[G2Len](s.readLine())

    for i in 0 ..< FIELD_ELEMENTS_PER_BLOB:
      g1Monomial[i] = hexToByteArray[G1Len](s.readLine())
  except ValueError as ex:
    return err(ex.msg)
  except OSError as ex:
    return err(ex.msg)
  except IOError as ex:
    return err(ex.msg)

  loadTrustedSetup(g1Monomial, g1Lagrange, g2Monomial, precompute)

proc toCommitment*(ctx: KzgCtx,
                   blob: KzgBlob):
                     Result[KzgCommitment, string] {.gcsafe.} =
  var ret: KzgCommitment
  let res = blob_to_kzg_commitment(ret, blob.getPtr, ctx.val)
  verify(res, ret)

proc computeProof*(ctx: KzgCtx,
                   blob: KzgBlob,
                   z: KzgBytes32): Result[KzgProofAndY, string] {.gcsafe.} =
  var ret: KzgProofAndY
  let res = compute_kzg_proof(
    ret.proof,
    ret.y,
    blob.getPtr,
    z.getPtr,
    ctx.val)
  verify(res, ret)

proc computeProof*(ctx: KzgCtx,
                   blob: KzgBlob,
                   commitmentBytes: KzgBytes48): Result[KzgProof, string] {.gcsafe.} =
  var proof: KzgProof
  let res = compute_blob_kzg_proof(
    proof,
    blob.getPtr,
    commitmentBytes.getPtr,
    ctx.val)
  verify(res, proof)

proc cellsToBlob*(ctx: KzgCtx,
                   cells: openArray[KzgCell]): Result[KzgBlob, string] {.gcsafe.} =
  var blob: KzgBlob
  let res = cells_to_blob(
    blob,
    cells[0].getPtr)
  verify(res, blob)

proc computeCells*(ctx: KzgCtx,
                   blob: KzgBlob): Result[KzgCells, string] {.gcsafe.} =
  var ret: KzgCells
  let res = compute_cells_and_kzg_proofs(
    ret[0].getPtr,
    cast[ptr KzgProof](nil), # Don't compute proofs
    blob.getPtr,
    ctx.val)
  verify(res, ret)

proc computeCellsAndProofs*(ctx: KzgCtx,
                   blob: KzgBlob): Result[KzgCellsAndKzgProofs, string] {.gcsafe.} =
  var ret: KzgCellsAndKzgProofs
  var cellsPtr: ptr KzgCell = ret.cells[0].getPtr
  var proofsPtr: ptr KzgProof = ret.proofs[0].getPtr
  let res = compute_cells_and_kzg_proofs(
    cellsPtr,
    proofsPtr,
    blob.getPtr,
    ctx.val)
  verify(res, ret)

proc verifyProof*(ctx: KzgCtx,
                  commitment: KzgBytes48,
                  z: KzgBytes32, # Input Point
                  y: KzgBytes32, # Claimed Value
                  proof: KzgBytes48): Result[bool, string] {.gcsafe.} =
  var valid: bool
  let res = verify_kzg_proof(
    valid,
    commitment.getPtr,
    z.getPtr,
    y.getPtr,
    proof.getPtr,
    ctx.val)
  verify(res, valid)

proc verifyProof*(ctx: KzgCtx,
                  blob: KzgBlob,
                  commitment: KzgBytes48,
                  proof: KzgBytes48): Result[bool, string] {.gcsafe.} =
  var valid: bool
  let res = verify_blob_kzg_proof(
    valid,
    blob.getPtr,
    commitment.getPtr,
    proof.getPtr,
    ctx.val)
  verify(res, valid)

proc verifyProof*(ctx: KzgCtx,
                  commitment: KzgBytes48,
                  cellId: uint64,
                  cell: KzgCell,
                  proof: KzgBytes48): Result[bool, string] {.gcsafe.} =
  var valid: bool
  let res = verify_cell_kzg_proof(
    valid,
    commitment.getPtr,
    cellId,
    cell.getPtr,
    proof.getPtr,
    ctx.val)
  verify(res, valid)

proc verifyProofs*(ctx: KzgCtx,
                  blobs: openArray[KzgBlob],
                  commitments: openArray[KzgBytes48],
                  proofs: openArray[KzgBytes48]): Result[bool, string] {.gcsafe.} =
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

proc verifyProofs*(ctx: KzgCtx,
                   rowCommitments: openArray[KzgBytes48],
                   rowIndices: openArray[uint64],
                   columnIndices: openArray[uint64],
                   cells: openArray[KzgCell],
                   proofs: openArray[KzgBytes48]): Result[bool, string] {.gcsafe.} =
  if cells.len != rowIndices.len:
    return err($KZG_BADARGS)

  if cells.len != columnIndices.len:
    return err($KZG_BADARGS)

  if cells.len != proofs.len:
    return err($KZG_BADARGS)

  if cells.len == 0:
    return ok(true)

  if rowCommitments.len == 0:
    return err($KZG_BADARGS)

  var valid: bool
  let res = verify_cell_kzg_proof_batch(
    valid,
    rowCommitments[0].getPtr,
    rowCommitments.len.csize_t,
    rowIndices[0].getPtr,
    columnIndices[0].getPtr,
    cells[0].getPtr,
    proofs[0].getPtr,
    cells.len.csize_t,
    ctx.val)
  verify(res, valid)

proc recoverCells*(ctx: KzgCtx,
                   cellIds: openArray[uint64],
                   cells: openArray[KzgCell]): Result[KzgCells, string] {.gcsafe.} =
  if cells.len != cellIds.len:
    return err($KZG_BADARGS)

  if cells.len == 0:
    return err($KZG_BADARGS)

  var ret: KzgCells
  let res = recover_cells_and_kzg_proofs(
    ret[0].getPtr,
    cast[ptr KzgProof](nil), # No proofs
    cellIds[0].getPtr,
    cells[0].getPtr,
    cast[ptr KzgBytes48](nil), # No proofs
    cells.len.csize_t,
    ctx.val)
  verify(res, ret)

proc recoverCellsAndProofs*(ctx: KzgCtx,
                   cellIds: openArray[uint64],
                   cells: openArray[KzgCell],
                   proofs: openArray[KzgBytes48]): Result[KzgCellsAndKzgProofs, string] {.gcsafe.} =
  if cells.len != cellIds.len:
    return err($KZG_BADARGS)

  if proofs.len != cellIds.len:
    return err($KZG_BADARGS)

  if cells.len == 0:
    return err($KZG_BADARGS)

  var ret: KzgCellsAndKzgProofs
  var recoveredCellsPtr: ptr KzgCell = ret.cells[0].getPtr
  var recoveredProofsPtr: ptr KzgProof = ret.proofs[0].getPtr
  let res = recover_cells_and_kzg_proofs(
    recoveredCellsPtr,
    recoveredProofsPtr,
    cellIds[0].getPtr,
    cells[0].getPtr,
    proofs[0].getPtr,
    cells.len.csize_t,
    ctx.val)
  verify(res, ret)

##############################################################
# Zero overhead aliases that match the spec
##############################################################

template loadTrustedSetupFile*(input: File | string, precompute: Natural): untyped =
  loadTrustedSetup(input, precompute)

template freeTrustedSetup*(ctx: KzgCtx) =
  destroy(ctx)

template blobToKzgCommitment*(ctx: KzgCtx,
                   blob: KzgBlob): untyped =
  toCommitment(ctx, blob)

template computeKzgProof*(ctx: KzgCtx,
                   blob: KzgBlob,
                   z: KzgBytes32): untyped =
  computeProof(ctx, blob, z)

template computeBlobKzgProof*(ctx: KzgCtx,
                   blob: KzgBlob,
                   commitmentBytes: KzgBytes48): untyped =
  computeProof(ctx, blob, commitmentBytes)

template verifyKzgProof*(ctx: KzgCtx,
                   commitment: KzgBytes48,
                   z: KzgBytes32, # Input Point
                   y: KzgBytes32, # Claimed Value
                   proof: KzgBytes48): untyped =
  verifyProof(ctx, commitment, z, y, proof)

template verifyBlobKzgProof*(ctx: KzgCtx,
                   blob: KzgBlob,
                   commitment: KzgBytes48,
                   proof: KzgBytes48): untyped =
  verifyProof(ctx, blob, commitment, proof)

template verifyBlobKzgProofBatch*(ctx: KzgCtx,
                   blobs: openArray[KzgBlob],
                   commitments: openArray[KzgBytes48],
                   proofs: openArray[KzgBytes48]): untyped =
  verifyProofs(ctx, blobs, commitments, proofs)

template computeCellsAndKzgProofs*(ctx: KzgCtx,
                   blob: KzgBlob): untyped =
  computeCellsAndProofs(ctx, blob)

template verifyCellKzgProof*(ctx: KzgCtx,
                   commitment: KzgBytes48,
                   cellId: uint64,
                   cell: KzgCell,
                   proof: KzgBytes48): untyped =
  verifyProof(ctx, commitment, cell, proof)

template verifyCellKzgProofBatch*(ctx: KzgCtx,
                   rowCommitments: openArray[KzgBytes48],
                   rowIndices: openArray[uint64],
                   columnIndices: openArray[uint64],
                   cells: openArray[KzgCell],
                   proofs: openArray[KzgBytes48]): untyped =
  verifyProofs(ctx, rowCommitments, rowIndices, columnIndices, cells, proofs)

template recoverAllCells*(ctx: KzgCtx,
                   cellIds: openArray[uint64],
                   cells: openArray[KzgCell]): untyped =
  recoverCells(ctx, cellIds, cells)

{. pop .}
