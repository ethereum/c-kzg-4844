{.used.}

import
  unittest2,
  ../kzg_ex,
  ./types

proc createKateBlobs(n: int): KateBlobs =
  var blob: KZGBlob
  for i in 0..<n:
    discard urandom(blob.bytes)
    for i in 0..<blob.bytes.len:
      # don't overflow modulus
      if blob.bytes[i] > MAX_TOP_BYTE and i %% 32 == 0:
        blob.bytes[i] = MAX_TOP_BYTE
    result.blobs.add(blob)

  for i in 0..<n:
    let res = toCommitment(result.blobs[i])
    doAssert res.isOk
    result.kates.add(res.get)

suite "verify proof (extended version)":
  test "load trusted setup from string":
    let res = KZG.loadTrustedSetupFromString(trustedSetup, 0)
    check res.isOk

  test "verify batch proof success":
    let kb = createKateBlobs(nblobs)
    var kp: array[nblobs, KZGProof]
    for i in 0..<nblobs:
      let pres = computeProof(kb.blobs[i], kb.kates[i])
      check pres.isOk
      kp[i] = pres.get

    let res = verifyProofs(kb.blobs, kb.kates, kp)
    check res.isOk
    check res.get == true

  test "verify batch proof failure":
    let kb = createKateBlobs(nblobs)
    var kp: array[nblobs, KZGProof]
    for i in 0..<nblobs:
      let pres = computeProof(kb.blobs[i], kb.kates[i])
      check pres.isOk
      kp[i] = pres.get

    let other = createKateBlobs(nblobs)
    var badProofs: array[nblobs, KZGProof]
    for i in 0..<nblobs:
      let pres = computeProof(other.blobs[i], other.kates[i])
      check pres.isOk
      badProofs[i] = pres.get

    let res = verifyProofs(kb.blobs, kb.kates, badProofs)
    check res.isOk
    check res.get == false

  test "verify blob proof":
    let kp = computeProof(blob, commitment)
    check kp.isOk

    let res = verifyProof(blob, commitment, kp.get)
    check res.isOk

  test "verify proof":
    let kp = computeProof(blob, inputPoint)
    check kp.isOk
    check kp.get.proof == proof
    check kp.get.y == claimedValue

    let res = verifyProof(commitment, inputPoint, claimedValue, kp.get.proof)
    check res.isOk

  test "template aliases":
    # no need to check return value
    # only test if those templates can be compiled successfully
    check KZG.freeTrustedSetup().isOk
    check KZG.loadTrustedSetupFile(trustedSetupFile, 0).isOk
    discard blobToKZGCommitment(blob)
    let kp = computeKZGProof(blob, inputPoint)
    discard computeBlobKZGProof(blob, commitment)
    discard verifyKZGProof(commitment, inputPoint, claimedValue, kp.get.proof)
    discard verifyBlobKZGProof(blob, commitment, proof)
    let kb = createKateBlobs(1)
    discard verifyBlobKZGProofBatch(kb.blobs, kb.kates, [kp.get.proof])

  test "load trusted setup more than once":
    let res = KZG.loadTrustedSetupFromString(trustedSetup, 0)
    check res.isErr
