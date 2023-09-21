{.used.}

import
  std/[streams, strutils],
  unittest2,
  stew/byteutils,
  ../kzg_abi,
  ./types

proc readSetup(): KzgSettings =
  var s = newFileStream(trustedSetupFile)

  doAssert(s.isNil.not,
    "FAILED TO OPEN: " & trustedSetupFile)

  let fieldElems = s.readLine().parseInt()
  let numG2 = s.readLine().parseInt()

  doAssert(fieldElems != 0)
  doAssert(numG2 != 0)

  var
    g1Bytes = newSeq[byte](fieldElems * 48)
    g2Bytes = newSeq[byte](numG2 * 96)

  for i in 0 ..< fieldElems:
    let z = hexToByteArray[48](s.readLine())
    g1Bytes[i*48 ..< i*48+48] = z[0..<48]

  for i in 0 ..< numG2:
    let z = hexToByteArray[96](s.readLine())
    g2Bytes[i*96 ..< i*96+96] = z[0..<96]

  let res = load_trusted_setup(result,
    g1Bytes[0].addr, fieldElems.csize_t,
    g2Bytes[0].addr, numG2.csize_t)

  doAssert(res == KZG_OK,
    "ERROR: " & $res)

proc readSetup(filename: string): KzgSettings =
  var file = open(filename)
  let ret =  load_trusted_setup_file(result, file)
  doAssert ret == KZG_OK
  file.close()

proc createKateBlobs(s: KzgSettings, n: int): KateBlobs =
  var blob = newSeq[byte](s.bytesPerBlob)
  for i in 0..<n:
    discard urandom(blob)
    for i in 0..<blob.len:
      # don't overflow modulus
      if blob[i] > MAX_TOP_BYTE and i %% BYTES_PER_FIELD_ELEMENT == 0:
        blob[i] = MAX_TOP_BYTE
    result.blobs.add(blob)

  for i in 0..<n:
    var kate: KzgCommitment
    doAssert blob_to_kzg_commitment(kate, addr result.blobs[i][0], s) == KZG_OK
    result.kates.add(kate)

let
  kzgs = readSetup()

suite "verify proof (abi)":
  let
    settings = readSetup(trustedSetupFile)
    bytesPerBlob = settings.bytesPerBlob.int

  var
    lcblob = blob

  test "verify batch proof success":
    var kb = kzgs.createKateBlobs(nblobs)
    var kp: array[nblobs, KzgProof]

    for i in 0..<nblobs:
      let res = compute_blob_kzg_proof(kp[i], addr kb.blobs[i][0], kb.kates[i], kzgs)
      check res == KZG_OK

    var blobs = newSeqOfCap[byte](kb.blobs.len * bytesPerBlob)
    for x in kb.blobs:
      blobs.add x

    var ok: bool
    let res = verify_blob_kzg_proof_batch(ok,
                         blobs[0].addr,
                         kb.kates[0].addr,
                         kp[0].addr,
                         csize_t(nblobs),
                         kzgs)
    check res == KZG_OK
    check ok

  test "verify batch proof failure":
    var kb = kzgs.createKateBlobs(nblobs)
    var kp: array[nblobs, KzgProof]

    for i in 0..<nblobs:
      let res = compute_blob_kzg_proof(kp[i], addr kb.blobs[i][0], kb.kates[i], kzgs)
      check res == KZG_OK

    var other = kzgs.createKateBlobs(nblobs)
    for i in 0..<nblobs:
      let res = compute_blob_kzg_proof(kp[i], addr other.blobs[i][0], other.kates[i], kzgs)
      check res == KZG_OK

    var blobs = newSeqOfCap[byte](kb.blobs.len * bytesPerBlob)
    for x in kb.blobs:
      blobs.add x

    var ok: bool
    let res = verify_blob_kzg_proof_batch(ok,
                         blobs[0].addr,
                         kb.kates[0].addr,
                         kp[0].addr,
                         csize_t(nblobs),
                         kzgs)
    check res == KZG_OK
    check ok == false

  test "verify blob proof":
    var kp: KzgProof
    var res = compute_blob_kzg_proof(kp, addr lcblob[0], commitment, kzgs)
    check res == KZG_OK

    var ok: bool
    res = verify_blob_kzg_proof(ok, addr lcblob[0], commitment, kp, kzgs)
    check res == KZG_OK
    check ok

  test "verify proof":
    var kp: KzgProof
    var ky: KzgBytes32
    var res = compute_kzg_proof(kp, ky, addr lcblob[0], inputPoint, kzgs)
    check res == KZG_OK
    check kp == proof
    check ky == claimedValue

    var ok: bool
    res = verify_kzg_proof(ok, commitment, inputPoint, claimedValue, kp, kzgs)
    check res == KZG_OK
    check ok

  free_trusted_setup(settings)
