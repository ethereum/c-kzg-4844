{.used.}

import
  unittest2,
  ../kzg_ex,
  ./types

proc createKateBlobs(n: int): KateBlobs =
  var blob: KzgBlob
  for i in 0..<n:
    discard urandom(blob)
    for i in 0..<len(blob):
      # don't overflow modulus
      if blob[i] > MAX_TOP_BYTE and i %% BYTES_PER_FIELD_ELEMENT == 0:
        blob[i] = MAX_TOP_BYTE
    result.blobs.add(blob)

  for i in 0..<n:
    let res = toCommitment(result.blobs[i])
    doAssert res.isOk
    result.kates.add(res.get)

suite "verify proof (extended version)":
  test "load trusted setup from string":
    let res = Kzg.loadTrustedSetupFromString(trustedSetup)
    check res.isOk

  test "verify batch proof success":
    let kb = createKateBlobs(nblobs)
    var kp: array[nblobs, KzgProof]
    for i in 0..<nblobs:
      let pres = computeProof(kb.blobs[i], kb.kates[i])
      check pres.isOk
      kp[i] = pres.get

    let res = verifyProofs(kb.blobs, kb.kates, kp)
    check res.isOk
    check res.get == true

  test "verify batch proof failure":
    let kb = createKateBlobs(nblobs)
    var kp: array[nblobs, KzgProof]
    for i in 0..<nblobs:
      let pres = computeProof(kb.blobs[i], kb.kates[i])
      check pres.isOk
      kp[i] = pres.get

    let other = createKateBlobs(nblobs)
    var badProofs: array[nblobs, KzgProof]
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
    check Kzg.freeTrustedSetup().isOk
    check Kzg.loadTrustedSetupFile(trustedSetupFile).isOk
    discard blobToKzgCommitment(blob)
    let kp = computeKzgProof(blob, inputPoint)
    discard computeBlobKzgProof(blob, commitment)
    discard verifyKzgProof(commitment, inputPoint, claimedValue, kp.get.proof)
    discard verifyBlobKzgProof(blob, commitment, proof)
    let kb = createKateBlobs(1)
    discard verifyBlobKzgProofBatch(kb.blobs, kb.kates, [kp.get.proof])

  test "load trusted setup more than once":
    let res = Kzg.loadTrustedSetupFromString(trustedSetup)
    check res.isErr
