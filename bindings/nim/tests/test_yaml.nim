{.used.}

import
  std/[os, strutils, streams],
  unittest2, yaml,
  stew/byteutils,
  ../kzg,
  ./types

const
  testBase = kzgPath & "tests/"
  BLOB_TO_KZG_COMMITMENT_TESTS = testBase & "blob_to_kzg_commitment"
  COMPUTE_KZG_PROOF_TESTS      = testBase & "compute_kzg_proof"
  COMPUTE_BLOB_KZG_PROOF_TESTS = testBase & "compute_blob_kzg_proof"
  VERIFY_KZG_PROOF_TESTS       = testBase & "verify_kzg_proof"
  VERIFY_BLOB_KZG_PROOF_TESTS  = testBase & "verify_blob_kzg_proof"
  VERIFY_BLOB_KZG_PROOF_BATCH_TESTS = testBase & "verify_blob_kzg_proof_batch"

proc toTestName(x: string): string =
  let parts = x.split(DirSep)
  parts[^2]

proc loadYaml(filename: string): YamlNode =
  var s = newFileStream(filename)
  load(s, result)
  s.close()

proc fromHex(T: type, x: string): T =
  if (x.len - 2) div 2 > sizeof(T):
    raise newException(ValueError, "invalid hex")
  hexToByteArray[sizeof(T)](x)

proc fromHex(T: type, x: YamlNode): T =
  T.fromHex(x.content)

proc fromHexList(T: type, xList: YamlNode): seq[T] =
  for x in xList:
    result.add(T.fromHex(x.content))

suite "yaml tests":
  var ctx: KzgCtx

  test "load trusted setup from string":
    let res = loadTrustedSetupFromString(trustedSetup)
    check res.isOk
    ctx = res.get

  for filename in walkDirRec(BLOB_TO_KZG_COMMITMENT_TESTS):
    test toTestName(filename):
      let
        n = loadYaml(filename)
        blob = KzgBlob.fromHex(n["input"]["blob"])
        res = ctx.toCommitment(blob)

      if res.isErr:
        check n["output"].content == "null"
      else:
        let kate = KzgCommitment.fromHex(n["output"])
        check kate == res.get

  for filename in walkDirRec(COMPUTE_KZG_PROOF_TESTS):
    test toTestName(filename):
      let
        n = loadYaml(filename)
        blob = KzgBlob.fromHex(n["input"]["blob"])
        zBytes = KzgBytes32.fromHex(n["input"]["z"])
        res = ctx.computeProof(blob, zBytes)

      if res.isErr:
        check n["output"].content == "null"
      else:
        let proof = KzgProof.fromHex(n["output"])
        check proof == res.get

  for filename in walkDirRec(COMPUTE_BLOB_KZG_PROOF_TESTS):
    test toTestName(filename):
      let
        n = loadYaml(filename)
        blob = KzgBlob.fromHex(n["input"]["blob"])
        res = ctx.computeProof(blob)

      if res.isErr:
        check n["output"].content == "null"
      else:
        let proof = KzgProof.fromHex(n["output"])
        check proof == res.get

  for filename in walkDirRec(VERIFY_KZG_PROOF_TESTS):
    test toTestName(filename):
      let
        n = loadYaml(filename)
        commitment = KzgCommitment.fromHex(n["input"]["commitment"])
        z = KzgBytes32.fromHex(n["input"]["z"])
        y = KzgBytes32.fromHex(n["input"]["y"])
        proof = KzgProof.fromHex(n["input"]["proof"])

      let res = ctx.verifyProof(commitment, z, y, proof)
      if res.isErr:
        check n["output"].content == "null"
      else:
        check n["output"].content == $res.get

  for filename in walkDirRec(VERIFY_BLOB_KZG_PROOF_TESTS):
    test toTestName(filename):
      let
        n = loadYaml(filename)
        blob = KzgBlob.fromHex(n["input"]["blob"])
        commitment = KzgCommitment.fromHex(n["input"]["commitment"])
        proof = KzgProof.fromHex(n["input"]["proof"])

      let res = ctx.verifyProof(blob, commitment, proof)
      if res.isErr:
        check n["output"].content == "null"
      else:
        check n["output"].content == $res.get

  for filename in walkDirRec(VERIFY_BLOB_KZG_PROOF_BATCH_TESTS):
    test toTestName(filename):
      let
        n = loadYaml(filename)
        blobs = KzgBlob.fromHexList(n["input"]["blobs"])
        commitments = KzgCommitment.fromHexList(n["input"]["commitments"])
        proofs = KzgProof.fromHexList(n["input"]["proofs"])
        res = ctx.verifyProofs(blobs, commitments, proofs)

      if res.isErr:
        check n["output"].content == "null"
      else:
        check n["output"].content == $res.get
