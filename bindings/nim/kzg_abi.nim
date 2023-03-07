############################################################
# FFI to C functions
############################################################

import
  std/[strformat, strutils]

from os import DirSep

const
  # FIELD_ELEMENTS_PER_BLOB is overrideable from
  # compiler switch -d: or --define:
  FIELD_ELEMENTS_PER_BLOB* {.strdefine.} = 4096
  # kzgPath: c-kzg-4844 project path, removing 3 last elem
  kzgPath  = currentSourcePath.rsplit(DirSep, 3)[0] & "/"
  blstPath = kzgPath & "blst/"
  srcPath  = kzgPath & "src/"
  bindingsPath = blstPath & "bindings"

when not defined(kzgExternalBlst):
  # Use default blst shipped with c-kzg-4844
  {.compile: blstPath & "build/assembly.S".}
  {.compile: blstPath & "src/server.c"}

{.compile: srcPath & "c_kzg_4844.c"}

{.passc: "-I" & bindingsPath &
  " -DFIELD_ELEMENTS_PER_BLOB=" &
  fmt"{FIELD_ELEMENTS_PER_BLOB}".}
{.passc: "-I" & srcPath .}

const
  BYTES_PER_FIELD_ELEMENT* = 32
  KzgBlobSize* = FIELD_ELEMENTS_PER_BLOB*BYTES_PER_FIELD_ELEMENT

type
  KZG_RET* = distinct cint

const
  KZG_OK*      = (0).KZG_RET
  KZG_BADARGS* = (1).KZG_RET
  KZG_ERROR*   = (2).KZG_RET
  KZG_MALLOC*  = (3).KZG_RET

proc `$`*(x: KZG_RET): string =
  case x
  of KZG_OK: "ok"
  of KZG_BADARGS: "kzg badargs"
  of KZG_ERROR: "kzg error"
  of KZG_MALLOC: "kzg malloc error"
  else: "kzg unknown error"

proc `==`*(a, b: KZG_RET): bool =
  a.cint == b.cint

type
  KzgBlob* = array[KzgBlobSize, byte]

  KzgSettings* {.importc: "KZGSettings",
    header: "c_kzg_4844.h", byref.} = object

  KzgBytes48* = array[48, byte]
  KzgBytes32* = array[32, byte]

  KzgCommitment* = KzgBytes48
  KzgProof* = KzgBytes48

{.pragma: kzg_abi, importc, cdecl, header: "c_kzg_4844.h".}

proc load_trusted_setup*(res: KzgSettings,
                         g1Bytes: ptr byte, # n1 * 48 bytes
                         n1: csize_t,
                         g2Bytes: ptr byte, # n2 * 96 bytes
                         n2: csize_t): KZG_RET {.kzg_abi.}

proc load_trusted_setup_file*(res: KzgSettings,
                         input: File): KZG_RET {.kzg_abi.}

proc free_trusted_setup*(s: KzgSettings) {.kzg_abi.}

proc blob_to_kzg_commitment*(res: var KzgCommitment,
                         blob: KzgBlob,
                         s: KzgSettings): KZG_RET {.kzg_abi.}

proc compute_kzg_proof*(res: var KzgProof,
                         blob: KzgBlob,
                         zBytes: KzgBytes32,
                         s: KzgSettings): KZG_RET {.kzg_abi.}

proc compute_blob_kzg_proof*(res: var KzgProof,
                         blob: KzgBlob,
                         s: KzgSettings): KZG_RET {.kzg_abi.}

proc verify_kzg_proof*(res: var bool,
                         commitmentBytes: KzgCommitment,
                         zBytes: KzgBytes32,
                         yBytes: KzgBytes32,
                         proofBytes: KzgProof,
                         s: KzgSettings): KZG_RET {.kzg_abi.}

proc verify_blob_kzg_proof*(res: var bool,
                         blob: KzgBlob,
                         commitmentsBytes: KzgCommitment,
                         proofBytes: KzgProof,
                         s: KzgSettings): KZG_RET {.kzg_abi.}

proc verify_blob_kzg_proof_batch*(res: var bool,
                         blobs: ptr KzgBlob,
                         commitmentsBytes: ptr KzgCommitment,
                         proofBytes: ptr KzgProof,
                         n: csize_t,
                         s: KzgSettings): KZG_RET {.kzg_abi.}
