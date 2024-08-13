{.used.}

import
  std/[os, sequtils, strutils, streams],
  unittest2, yaml,
  ../kzg,
  ./types

# we want to use our own fromHex
import
  stew/byteutils except fromHex

const
  testBase = kzgPath & "tests/"
  BLOB_TO_KZG_COMMITMENT_TESTS       = testBase & "blob_to_kzg_commitment"
  COMPUTE_KZG_PROOF_TESTS            = testBase & "compute_kzg_proof"
  COMPUTE_BLOB_KZG_PROOF_TESTS       = testBase & "compute_blob_kzg_proof"
  VERIFY_KZG_PROOF_TESTS             = testBase & "verify_kzg_proof"
  VERIFY_BLOB_KZG_PROOF_TESTS        = testBase & "verify_blob_kzg_proof"
  VERIFY_BLOB_KZG_PROOF_BATCH_TESTS  = testBase & "verify_blob_kzg_proof_batch"
  COMPUTE_CELLS_AND_KZG_PROOFS_TESTS = testBase & "compute_cells_and_kzg_proofs"
  RECOVER_CELLS_AND_KZG_PROOFS_TESTS = testBase & "recover_cells_and_kzg_proofs"
  VERIFY_CELL_KZG_PROOF_BATCH_TESTS  = testBase & "verify_cell_kzg_proof_batch"

proc toTestName(x: string): string =
  let parts = x.split(DirSep)
  parts[^2]

proc loadYaml(filename: string): YamlNode =
  var s = newFileStream(filename)
  load(s, result)
  s.close()

proc fromHex(T: type, x: string): T =
  if (x.len - 2) div 2 > sizeof(result.bytes):
    raise newException(ValueError, "invalid hex")
  result.bytes = hexToByteArray(x, sizeof(result.bytes))

proc fromHex(T: type, x: YamlNode): T =
  T.fromHex(x.content)

proc fromHexList(T: type, xList: YamlNode): seq[T] =
  for x in xList:
    result.add(T.fromHex(x.content))

proc fromIntList(T: type, xList: YamlNode): seq[T] =
  for x in xList:
    result.add(x.content.parseInt().T)

template runTests(folder: string, body: untyped) =
  let test_files = walkDirRec(folder).toSeq()
  check test_files.len > 0
  for test_file in test_files:
    test toTestName(test_file):
      # nim template is hygienic, {.inject.} will allow body to
      # access injected symbol in current scope
      let n {.inject.} = loadYaml(test_file)
      try:
        body
      except ValueError:
        check n["output"].content == "null"

template checkRes(res, body: untyped) =
  if res.isErr:
    check n["output"].content == "null"
  else:
    body

template checkBool(res: untyped) =
  checkRes(res):
    check n["output"].content == $res.get

template checkBytes48(res: untyped) =
  checkRes(res):
    let bytes = KZGBytes48.fromHex(n["output"])
    check bytes == res.get

suite "yaml tests":
  var ctx: KZGCtx

  test "load trusted setup from string":
    let res = loadTrustedSetupFromString(trustedSetup, 8)
    check res.isOk
    ctx = res.get

  runTests(BLOB_TO_KZG_COMMITMENT_TESTS):
    let
      blob = KZGBlob.fromHex(n["input"]["blob"])
      res = ctx.toCommitment(blob)
    checkBytes48(res)

  runTests(COMPUTE_KZG_PROOF_TESTS):
    let
      blob = KZGBlob.fromHex(n["input"]["blob"])
      zBytes = KZGBytes32.fromHex(n["input"]["z"])
      res = ctx.computeProof(blob, zBytes)

    checkRes(res):
      let proof = KZGProof.fromHex(n["output"][0])
      check proof == res.get.proof
      let y = KZGBytes32.fromHex(n["output"][1])
      check y == res.get.y

  runTests(COMPUTE_BLOB_KZG_PROOF_TESTS):
    let
      blob = KZGBlob.fromHex(n["input"]["blob"])
      commitment = KZGCommitment.fromHex(n["input"]["commitment"])
      res = ctx.computeProof(blob, commitment)
    checkBytes48(res)

  runTests(VERIFY_KZG_PROOF_TESTS):
    let
      commitment = KZGCommitment.fromHex(n["input"]["commitment"])
      z = KZGBytes32.fromHex(n["input"]["z"])
      y = KZGBytes32.fromHex(n["input"]["y"])
      proof = KZGProof.fromHex(n["input"]["proof"])
      res = ctx.verifyProof(commitment, z, y, proof)
    checkBool(res)

  runTests(VERIFY_BLOB_KZG_PROOF_TESTS):
    let
      blob = KZGBlob.fromHex(n["input"]["blob"])
      commitment = KZGCommitment.fromHex(n["input"]["commitment"])
      proof = KZGProof.fromHex(n["input"]["proof"])
      res = ctx.verifyProof(blob, commitment, proof)
    checkBool(res)

  runTests(VERIFY_BLOB_KZG_PROOF_BATCH_TESTS):
    let
      blobs = KZGBlob.fromHexList(n["input"]["blobs"])
      commitments = KZGCommitment.fromHexList(n["input"]["commitments"])
      proofs = KZGProof.fromHexList(n["input"]["proofs"])
      res = ctx.verifyProofs(blobs, commitments, proofs)
    checkBool(res)

  runTests(COMPUTE_CELLS_AND_KZG_PROOFS_TESTS):
    let
      blob = KZGBlob.fromHex(n["input"]["blob"])
      res = ctx.computeCellsAndProofs(blob)

    checkRes(res):
      let cells = KZGCell.fromHexList(n["output"][0])
      check cells == res.get.cells
      let proofs = KZGProof.fromHexList(n["output"][1])
      check proofs == res.get.proofs

  runTests(RECOVER_CELLS_AND_KZG_PROOFS_TESTS):
    let
      cellIndices = uint64.fromIntList(n["input"]["cell_indices"])
      cells = KZGCell.fromHexList(n["input"]["cells"])
      res = ctx.recoverCellsAndProofs(cellIndices, cells)

    checkRes(res):
      let expectedCells = KZGCell.fromHexList(n["output"][0])
      check expectedCells == res.get.cells
      let expectedProofs = KZGProof.fromHexList(n["output"][1])
      check expectedProofs == res.get.proofs

  runTests(VERIFY_CELL_KZG_PROOF_BATCH_TESTS):
    let
      commitments = KZGCommitment.fromHexList(n["input"]["commitments"])
      cellIndices = uint64.fromIntList(n["input"]["cell_indices"])
      cells = KZGCell.fromHexList(n["input"]["cells"])
      proofs = KZGProof.fromHexList(n["input"]["proofs"])
      res = ctx.verifyProofs(commitments, cellIndices, cells, proofs)
    checkBool(res)