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

# Private constants
const
  FIELD_ELEMENTS_PER_BLOB = 4096
  CELLS_PER_EXT_BLOB = 128

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

proc loadTrustedSetup*(g1MonomialBytes: openArray[byte],
                       g1LagrangeBytes: openArray[byte],
                       g2MonomialBytes: openArray[byte],
                       precompute: Natural):
                         Result[KzgCtx, string] =
  if g1MonomialBytes.len == 0 or g1LagrangeBytes.len == 0 or g2MonomialBytes.len == 0:
    return err($KZG_BADARGS)

  let
    ctx = newKzgCtx()
    res = load_trusted_setup(ctx.val,
      g1MonomialBytes[0].getPtr,
      g1MonomialBytes.len.csize_t,
      g1LagrangeBytes[0].getPtr,
      g1LagrangeBytes.len.csize_t,
      g2MonomialBytes[0].getPtr,
      g2MonomialBytes.len.csize_t,
      precompute.csize_t)
  verify(res, ctx)

proc loadTrustedSetupFromString*(input: string, precompute: Natural): Result[KzgCtx, string] =
  const
    NumG1 = FIELD_ELEMENTS_PER_BLOB
    NumG2 = 65
    G1Len = 48
    G2Len = 96

  var
    s = newStringStream(input)
    g1MonomialBytes: seq[byte] = newSeq[byte](NumG1 * G1Len)
    g1LagrangeBytes: seq[byte] = newSeq[byte](NumG1 * G1Len)
    g2MonomialBytes: seq[byte] = newSeq[byte](NumG2 * G2Len)

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
      for j in 0 ..< G1Len:
        g1LagrangeBytes[i * G1Len + j] = p[j]

    for i in 0 ..< NumG2:
      let p = hexToByteArray[G2Len](s.readLine())
      for j in 0 ..< G2Len:
        g2MonomialBytes[i * G2Len + j] = p[j]

    for i in 0 ..< NumG1:
      let p = hexToByteArray[G1Len](s.readLine())
      for j in 0 ..< G1Len:
        g1MonomialBytes[i * G1Len + j] = p[j]

  except ValueError as ex:
    return err(ex.msg)
  except OSError as ex:
    return err(ex.msg)
  except IOError as ex:
    return err(ex.msg)

  loadTrustedSetup(g1MonomialBytes, g1LagrangeBytes, g2MonomialBytes, precompute)

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
                   commitments: openArray[KzgBytes48],
                   cellIndices: openArray[uint64],
                   cells: openArray[KzgCell],
                   proofs: openArray[KzgBytes48]): Result[bool, string] {.gcsafe.} =
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

proc recoverCellsAndProofs*(ctx: KzgCtx,
                   cellIndices: openArray[uint64],
                   cells: openArray[KzgCell]): Result[KzgCellsAndKzgProofs, string] {.gcsafe.} =
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

template recoverCellsAndKzgProofs*(ctx: KzgCtx,
                   cellIndices: openArray[uint64],
                   cells: openArray[KzgCell]): untyped =
  recoverCellsAndProofs(ctx, cellIndices, cells)

template verifyCellKzgProofBatch*(ctx: KzgCtx,
                   commitments: openArray[KzgBytes48],
                   cellIndices: openArray[uint64],
                   cells: openArray[KzgCell],
                   proofs: openArray[KzgBytes48]): untyped =
  verifyProofs(ctx, commitments, cellIndices, cells, proofs)

{. pop .}
