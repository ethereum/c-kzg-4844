{.used.}

import
  unittest2,
  ../kzg,
  ./types

proc createKateBlobs(ctx: KzgCtx, n: int): KateBlobs =
  var blob: KzgBlob
  for i in 0..<n:
    discard urandom(blob)
    for i in 0..<len(blob):
      # don't overflow modulus
      if blob[i] > MAX_TOP_BYTE and i %% BYTES_PER_FIELD_ELEMENT == 31:
        blob[i] = MAX_TOP_BYTE
    result.blobs.add(blob)

  for i in 0..<n:
    let res = ctx.toCommitment(result.blobs[i])
    doAssert res.isOk
    result.kates.add(res.get)

suite "verify proof (high-level)":
  var ctx: KzgCtx

  test "load trusted setup from string":
    let res = loadTrustedSetupFromString(trustedSetup)
    check res.isOk
    ctx = res.get

  test "verify batch proof success":
    let kb = ctx.createKateBlobs(nblobs)
    var kp: array[nblobs, KzgProof]
    for i in 0..<nblobs:
      let pres = ctx.computeProof(kb.blobs[i])
      check pres.isOk
      kp[i] = pres.get

    let res = ctx.verifyProofs(kb.blobs, kb.kates, kp)
    check res.isOk
    check res.get == true

  test "verify batch proof failure":
    let kb = ctx.createKateBlobs(nblobs)
    var kp: array[nblobs, KzgProof]
    for i in 0..<nblobs:
      let pres = ctx.computeProof(kb.blobs[i])
      check pres.isOk
      kp[i] = pres.get

    let other = ctx.createKateBlobs(nblobs)
    var badProofs: array[nblobs, KzgProof]
    for i in 0..<nblobs:
      let pres = ctx.computeProof(other.blobs[i])
      check pres.isOk
      badProofs[i] = pres.get

    let res = ctx.verifyProofs(kb.blobs, kb.kates, badProofs)
    check res.isOk
    check res.get == false

  test "verify blob proof":
    let kp = ctx.computeProof(blob)
    check kp.isOk

    let res = ctx.verifyProof(blob, commitment, kp.get)
    check res.isOk

  test "verify proof":
    let kp = ctx.computeProof(blob, inputPoint)
    check kp.isOk
    check kp.get == proof

    let res = ctx.verifyProof(commitment, inputPoint, claimedValue, kp.get)
    check res.isOk
