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
    g1: array[FIELD_ELEMENTS_PER_BLOB, G1Data]
    g2: array[NumG2, G2Data]

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
      g1[i] = hexToByteArray[G1Len](s.readLine())

    for i in 0 ..< NumG2:
      g2[i] = hexToByteArray[G2Len](s.readLine())
  except ValueError as ex:
    return err(ex.msg)
  except OSError as ex:
    return err(ex.msg)
  except IOError as ex:
    return err(ex.msg)

  loadTrustedSetup(g1, g2)

proc toCommitment*(ctx: KzgCtx,
                   blob: KzgBlob):
                     Result[KzgCommitment, string] {.gcsafe.} =
  var ret: KzgCommitment
  let res = blob_to_kzg_commitment(ret, blob, ctx.val)
  verify(res, ret)

proc computeProof*(ctx: KzgCtx,
                   blob: KzgBlob,
                   z: KzgBytes32): Result[KzgProofAndY, string] {.gcsafe.} =
  var ret: KzgProofAndY
  let res = compute_kzg_proof(
    ret.proof,
    ret.y,
    blob,
    z,
    ctx.val)
  verify(res, ret)

proc computeProof*(ctx: KzgCtx,
                   blob: KzgBlob,
                   commitmentBytes: KzgBytes48): Result[KzgProof, string] {.gcsafe.} =
  var proof: KzgProof
  let res = compute_blob_kzg_proof(
    proof,
    blob,
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
                  blob: KzgBlob,
                  commitment: KzgBytes48,
                  proof: KzgBytes48): Result[bool, string] {.gcsafe.} =
  var valid: bool
  let res = verify_blob_kzg_proof(
    valid,
    blob,
    commitment,
    proof,
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

##############################################################
# Zero overhead aliases that match the spec
##############################################################

template loadTrustedSetupFile*(input: File | string): untyped =
  loadTrustedSetup(input)

template freeTrustedSetup*(ctx: KzgCtx) =
  free_trusted_setup(ctx.val)
  
template blobToKzgCommitment*(ctx: KzgCtx,
                   blob: KzgBlob): untyped =
  toCommitment(ctx, blob)

template computeKzgProof*(ctx: KzgCtx,
                   blob: KzgBlob, z: KzgBytes32): untyped =
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

{. pop .}
