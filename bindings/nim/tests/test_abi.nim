{.used.}

import
  std/[streams, strutils],
  unittest2,
  stew/byteutils,
  ../kzg_abi,
  ./types

type
  CKateBlobs* = object
    kates*: seq[CKzgCommitment]
    blobs*: seq[CKzgBlob]
    
proc readSetup(): CKzgSettings =
  var
    s = newFileStream(trustedSetupFile)
    g1Bytes: array[FIELD_ELEMENTS_PER_BLOB * 48, byte]
    g2Bytes: array[65 * 96, byte]

  doAssert(s.isNil.not,
    "FAILED TO OPEN: " & trustedSetupFile)

  let fieldElems = s.readLine().parseInt()
  doAssert fieldElems == FIELD_ELEMENTS_PER_BLOB
  let numG2 = s.readLine().parseInt()
  doAssert numG2 == 65

  for i in 0 ..< FIELD_ELEMENTS_PER_BLOB:
    let z = hexToByteArray[48](s.readLine())
    g1Bytes[i*48 ..< i*48+48] = z[0..<48]

  for i in 0 ..< 65:
    let z = hexToByteArray[96](s.readLine())
    g2Bytes[i*96 ..< i*96+96] = z[0..<96]

  let res = load_trusted_setup(result,
    g1Bytes[0].addr, FIELD_ELEMENTS_PER_BLOB,
    g2Bytes[0].addr, 65)

  doAssert(res == KZG_OK,
    "ERROR: " & $res)

proc readSetup(filename: string): CKzgSettings =
  var file = open(filename)
  let ret =  load_trusted_setup_file(result, file)
  doAssert ret == KZG_OK
  file.close()

proc createKateBlobs(s: CKzgSettings, n: int): CKateBlobs =
  for i in 0..<n:
    var blob: CKzgBlob
    discard urandom(blob.bytes)
    for i in 0..<blob.bytes.len:
      # don't overflow modulus
      if blob.bytes[i] > MAX_TOP_BYTE and i %% BYTES_PER_FIELD_ELEMENT == 0:
        blob.bytes[i] = MAX_TOP_BYTE
    result.blobs.add(blob)

  for i in 0..<n:
    var kate: CKzgCommitment
    doAssert blob_to_kzg_commitment(kate.addr, result.blobs[i].addr, s) == KZG_OK
    result.kates.add(kate)

let
  kzgs = readSetup()

suite "verify proof (abi)":
  let
    settings = readSetup(trustedSetupFile)

  var
    blob = CKzgBlob(bytes: blobBytes)
    commitment = CKzgCommitment(bytes: commitmentBytes)
    proof = CKzgProof(bytes: proofBytes)
    inputPoint = CKzgBytes32(bytes: inputPointBytes)
    claimedValue = CKzgBytes32(bytes: claimedValueBytes)

  test "verify batch proof success":
    var kb = kzgs.createKateBlobs(nblobs)
    var kp: array[nblobs, CKzgProof]

    for i in 0..<nblobs:
      let res = compute_blob_kzg_proof(kp[i].addr, kb.blobs[i].addr, kb.kates[i].addr, kzgs)
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
    var kp: array[nblobs, CKzgProof]

    for i in 0..<nblobs:
      let res = compute_blob_kzg_proof(kp[i].addr, kb.blobs[i].addr, kb.kates[i].addr, kzgs)
      check res == KZG_OK

    var other = kzgs.createKateBlobs(nblobs)
    for i in 0..<nblobs:
      let res = compute_blob_kzg_proof(kp[i].addr, other.blobs[i].addr, other.kates[i].addr, kzgs)
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
    var kp: CKzgProof
    var res = compute_blob_kzg_proof(kp.addr, blob.addr, commitment.addr, kzgs)
    check res == KZG_OK

    var ok: bool
    res = verify_blob_kzg_proof(ok, blob.addr, commitment.addr, kp.addr, kzgs)
    check res == KZG_OK
    check ok

  test "verify proof":
    var kp: CKzgProof
    var ky: CKzgBytes32
    var res = compute_kzg_proof(kp.addr, ky.addr, blob.addr, inputPoint.addr, kzgs)
    check res == KZG_OK
    check kp == proof
    check ky == claimedValue

    var ok: bool
    res = verify_kzg_proof(ok, commitment.addr, inputPoint.addr, claimedValue.addr, kp.addr, kzgs)
    check res == KZG_OK
    check ok

  free_trusted_setup(settings)
