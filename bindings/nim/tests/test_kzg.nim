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
      if blob[i] > MAX_TOP_BYTE and i %% BYTES_PER_FIELD_ELEMENT == 0:
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
      let pres = ctx.computeProof(kb.blobs[i], kb.kates[i])
      check pres.isOk
      kp[i] = pres.get

    let res = ctx.verifyProofs(kb.blobs, kb.kates, kp)
    check res.isOk
    check res.get == true

  test "verify batch proof failure":
    let kb = ctx.createKateBlobs(nblobs)
    var kp: array[nblobs, KzgProof]
    for i in 0..<nblobs:
      let pres = ctx.computeProof(kb.blobs[i], kb.kates[i])
      check pres.isOk
      kp[i] = pres.get

    let other = ctx.createKateBlobs(nblobs)
    var badProofs: array[nblobs, KzgProof]
    for i in 0..<nblobs:
      let pres = ctx.computeProof(other.blobs[i], other.kates[i])
      check pres.isOk
      badProofs[i] = pres.get

    let res = ctx.verifyProofs(kb.blobs, kb.kates, badProofs)
    check res.isOk
    check res.get == false

  test "verify blob proof":
    let kp = ctx.computeProof(blob, commitment)
    check kp.isOk

    let res = ctx.verifyProof(blob, commitment, kp.get)
    check res.isOk

  test "verify proof":
    let kp = ctx.computeProof(blob, inputPoint)
    check kp.isOk
    check kp.get.proof == proof
    check kp.get.y == claimedValue

    let res = ctx.verifyProof(commitment, inputPoint, claimedValue, kp.get.proof)
    check res.isOk

  test "template aliases":
    # no need to check return value
    # only test if those templates can be compiled successfully
    let res = loadTrustedSetupFile(trustedSetupFile)
    check res.isOk
    ctx = res.get

    discard ctx.blobToKzgCommitment(blob)
    let kp = ctx.computeKzgProof(blob, inputPoint)
    discard ctx.computeBlobKzgProof(blob, commitment)
    discard ctx.verifyKzgProof(commitment, inputPoint, claimedValue, kp.get.proof)
    discard ctx.verifyBlobKzgProof(blob, commitment, proof)

    let kb = ctx.createKateBlobs(1)
    discard ctx.verifyBlobKzgProofBatch(kb.blobs, kb.kates, [kp.get.proof])
