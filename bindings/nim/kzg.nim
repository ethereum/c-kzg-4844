############################################################
# Main API, wrapper on top of C FFI
############################################################

import
  std/[streams, strutils],
  stew/[results, byteutils],
  ./kzg_abi

export
  results,
  kzg_abi

type
  KzgCtx* = ref object
    val: KzgSettings

  KzgProofAndY* = object
    proof*: KzgProof
    y*: KzgBytes32

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
  free_trusted_setup(x.val)

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

template verifyBlob(ctx, blob: untyped) =
  if blob.len.uint64 != ctx.val.bytesPerBlob:
    return err($KZG_BADARGS)

##############################################################
# Public functions
##############################################################

proc loadTrustedSetup*(input: File): Result[KzgCtx, string] =
  let
    ctx = newKzgCtx()
    res = load_trusted_setup_file(ctx.val, input)
  verify(res, ctx)

proc loadTrustedSetup*(fileName: string): Result[KzgCtx, string] =
  try:
    let file = open(fileName)
    result = file.loadTrustedSetup()
    file.close()
  except IOError as ex:
    return err(ex.msg)

proc loadTrustedSetup*(g1: openArray[G1Data],
                       g2: openArray[G2Data]):
                         Result[KzgCtx, string] =
  if g1.len == 0 or g2.len == 0:
    return err($KZG_BADARGS)

  let
    ctx = newKzgCtx()
    res = load_trusted_setup(ctx.val,
      g1[0][0].getPtr,
      g1.len.csize_t,
      g2[0][0].getPtr,
      g2.len.csize_t)
  verify(res, ctx)

proc loadTrustedSetupFromString*(input: string): Result[KzgCtx, string] =
  const
    NumG2 = 65
    G1Len = G1Data.len
    G2Len = G2Data.len

  var
    s = newStringStream(input)
    g2: array[NumG2, G2Data]

  try:
    let fieldElems = s.readLine().parseInt()
    if fieldElems <= 0:
      return err("invalid field elemments per blob: $1" % [
        $fieldElems
      ])
    let numG2 = s.readLine().parseInt()
    if numG2 != NumG2:
      return err("invalid number of G2, expect $1, got $2" % [
        $NumG2, $numG2
      ])

    var g1 = newSeq[G1Data](fieldElems)
    for i in 0 ..< fieldElems:
      g1[i] = hexToByteArray[G1Len](s.readLine())

    for i in 0 ..< NumG2:
      g2[i] = hexToByteArray[G2Len](s.readLine())

    loadTrustedSetup(g1, g2)
  except ValueError as ex:
    err(ex.msg)
  except OSError as ex:
    err(ex.msg)
  except IOError as ex:
    err(ex.msg)

proc toCommitment*(ctx: KzgCtx,
                   blob: openArray[byte]):
                     Result[KzgCommitment, string] {.gcsafe.} =
  verifyBlob(ctx, blob)
  var ret: KzgCommitment
  let res = blob_to_kzg_commitment(ret, blob[0].getPtr, ctx.val)
  verify(res, ret)

proc computeProof*(ctx: KzgCtx,
                   blob: openArray[byte],
                   z: KzgBytes32): Result[KzgProofAndY, string] {.gcsafe.} =
  verifyBlob(ctx, blob)
  var ret: KzgProofAndY
  let res = compute_kzg_proof(
    ret.proof,
    ret.y,
    blob[0].getPtr,
    z,
    ctx.val)
  verify(res, ret)

proc computeProof*(ctx: KzgCtx,
                   blob: openArray[byte],
                   commitmentBytes: KzgBytes48): Result[KzgProof, string] {.gcsafe.} =
  verifyBlob(ctx, blob)
  var proof: KzgProof
  let res = compute_blob_kzg_proof(
    proof,
    blob[0].getPtr,
    commitmentBytes,
    ctx.val)
  verify(res, proof)

proc verifyProof*(ctx: KzgCtx,
                  commitment: KzgBytes48,
                  z: KzgBytes32, # Input Point
                  y: KzgBytes32, # Claimed Value
                  proof: KzgBytes48): Result[bool, string] {.gcsafe.} =
  var valid: bool
  let res = verify_kzg_proof(
    valid,
    commitment,
    z,
    y,
    proof,
    ctx.val)
  verify(res, valid)

proc verifyProof*(ctx: KzgCtx,
                  blob: openArray[byte],
                  commitment: KzgBytes48,
                  proof: KzgBytes48): Result[bool, string] {.gcsafe.} =
  verifyBlob(ctx, blob)
  var valid: bool
  let res = verify_blob_kzg_proof(
    valid,
    blob[0].getPtr,
    commitment,
    proof,
    ctx.val)
  verify(res, valid)

proc verifyProofs*(ctx: KzgCtx,
                  blobs: openArray[byte],
                  commitments: openArray[KzgBytes48],
                  proofs: openArray[KzgBytes48]): Result[bool, string] {.gcsafe.} =
  ## blobs is a flat byte array
  if blobs.len div ctx.val.bytesPerBlob.int != commitments.len:
    return err($KZG_BADARGS)

  # the number of blobs, commitments, and proofs should same
  if blobs.len div ctx.val.bytesPerBlob.int != proofs.len:
    return err($KZG_BADARGS)

  # reject blobs with extra bytes too!
  if blobs.len mod ctx.val.bytesPerBlob.int != 0:
    return err($KZG_BADARGS)

  if blobs.len == 0:
    return ok(true)

  var valid: bool
  let res = verify_blob_kzg_proof_batch(
    valid,
    blobs[0].getPtr,
    commitments[0].getPtr,
    proofs[0].getPtr,
    proofs.len.csize_t,
    ctx.val)
  verify(res, valid)

##############################################################
# Getters
##############################################################

template bytesPerblob*(ctx: KzgCtx): uint64 =
  ctx.val.bytesPerBlob

template fieldElementsPerBlob*(ctx: KzgCtx): uint64 =
  ctx.val.fieldElementsPerBlob

##############################################################
# Zero overhead aliases that match the spec
##############################################################

template loadTrustedSetupFile*(input: File | string): untyped =
  loadTrustedSetup(input)

template freeTrustedSetup*(ctx: KzgCtx) =
  free_trusted_setup(ctx.val)

template blobToKzgCommitment*(ctx: KzgCtx,
                   blob: openArray[byte]): untyped =
  toCommitment(ctx, blob)

template computeKzgProof*(ctx: KzgCtx,
                   blob: openArray[byte], z: KzgBytes32): untyped =
  computeProof(ctx, blob, z)

template computeBlobKzgProof*(ctx: KzgCtx,
                   blob: openArray[byte],
                   commitmentBytes: KzgBytes48): untyped =
  computeProof(ctx, blob, commitmentBytes)

template verifyKzgProof*(ctx: KzgCtx,
                   commitment: KzgBytes48,
                   z: KzgBytes32, # Input Point
                   y: KzgBytes32, # Claimed Value
                   proof: KzgBytes48): untyped =
  verifyProof(ctx, commitment, z, y, proof)

template verifyBlobKzgProof*(ctx: KzgCtx,
                   blob: openArray[byte],
                   commitment: KzgBytes48,
                   proof: KzgBytes48): untyped =
  verifyProof(ctx, blob, commitment, proof)

template verifyBlobKzgProofBatch*(ctx: KzgCtx,
                   blobs: openArray[byte],
                   commitments: openArray[KzgBytes48],
                   proofs: openArray[KzgBytes48]): untyped =
  verifyProofs(ctx, blobs, commitments, proofs)

{. pop .}
