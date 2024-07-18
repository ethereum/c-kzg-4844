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

  let n1 = s.readLine().parseInt()
  let n2 = s.readLine().parseInt()

  var
    g1MonomialBytes: seq[byte] = newSeq[byte](n1 * 48)
    g1LagrangeBytes: seq[byte] = newSeq[byte](n1 * 48)
    g2MonomialBytes: seq[byte] = newSeq[byte](n2 * 96)

  for i in 0 ..< n1:
    let z = hexToByteArray[48](s.readLine())
    g1LagrangeBytes[i*48 ..< i*48+48] = z[0..<48]

  for i in 0 ..< n2:
    let z = hexToByteArray[96](s.readLine())
    g2MonomialBytes[i*96 ..< i*96+96] = z[0..<96]

  for i in 0 ..< n1:
    let z = hexToByteArray[48](s.readLine())
    g1MonomialBytes[i*48 ..< i*48+48] = z[0..<48]

  let res = load_trusted_setup(result,
    g1MonomialBytes[0].addr,
    g1MonomialBytes.len.csize_t,
    g1LagrangeBytes[0].addr,
    g1LagrangeBytes.len.csize_t,
    g2MonomialBytes[0].addr,
    g2MonomialBytes.len.csize_t,
    0)

  doAssert(res == KZG_OK,
    "ERROR: " & $res)

proc readSetup(filename: string): KzgSettings =
  var file = open(filename)
  let ret =  load_trusted_setup_file(result, file, 0)
  doAssert ret == KZG_OK
  file.close()

proc createKateBlobs(s: KzgSettings, n: int): KateBlobs =
  for i in 0..<n:
    var blob: KzgBlob
    discard urandom(blob.bytes)
    for i in 0..<blob.bytes.len:
      # don't overflow modulus
      if blob.bytes[i] > MAX_TOP_BYTE and i %% 32 == 0:
        blob.bytes[i] = MAX_TOP_BYTE
    result.blobs.add(blob)

  for i in 0..<n:
    var kate: KzgCommitment
    doAssert blob_to_kzg_commitment(kate, result.blobs[i].addr, s) == KZG_OK
    result.kates.add(kate)

let
  kzgs = readSetup()

suite "verify proof (abi)":
  let
    settings = readSetup(trustedSetupFile)

  test "verify batch proof success":
    var kb = kzgs.createKateBlobs(nblobs)
    var kp: array[nblobs, KzgProof]

    for i in 0..<nblobs:
      let res = compute_blob_kzg_proof(kp[i], kb.blobs[i].addr, kb.kates[i].addr, kzgs)
      check res == KZG_OK

    var ok: bool
    let res = verify_blob_kzg_proof_batch(ok,
                         kb.blobs[0].addr,
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
      let res = compute_blob_kzg_proof(kp[i], kb.blobs[i].addr, kb.kates[i].addr, kzgs)
      check res == KZG_OK

    var other = kzgs.createKateBlobs(nblobs)
    for i in 0..<nblobs:
      let res = compute_blob_kzg_proof(kp[i], other.blobs[i].addr, other.kates[i].addr, kzgs)
      check res == KZG_OK

    var ok: bool
    let res = verify_blob_kzg_proof_batch(ok,
                         kb.blobs[0].addr,
                         kb.kates[0].addr,
                         kp[0].addr,
                         csize_t(nblobs),
                         kzgs)
    check res == KZG_OK
    check ok == false

  test "verify blob proof":
    var kp: KzgProof
    var res = compute_blob_kzg_proof(kp, blob.addr, commitment.addr, kzgs)
    check res == KZG_OK

    var ok: bool
    res = verify_blob_kzg_proof(ok, blob.addr, commitment.addr, kp.addr, kzgs)
    check res == KZG_OK
    check ok

  test "verify proof":
    var kp: KzgProof
    var ky: KzgBytes32
    var res = compute_kzg_proof(kp, ky, blob.addr, inputPoint.addr, kzgs)
    check res == KZG_OK
    check kp == proof
    check ky == claimedValue

    var ok: bool
    res = verify_kzg_proof(ok, commitment.addr, inputPoint.addr, claimedValue.addr, kp.addr, kzgs)
    check res == KZG_OK
    check ok

  free_trusted_setup(settings)
