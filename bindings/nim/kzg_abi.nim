############################################################
# FFI to C functions
############################################################

import
  std/strutils

from os import DirSep, AltSep

const
  # kzgPath: c-kzg-4844 project path, removing 3 last elem
  kzgPath  = currentSourcePath.rsplit({DirSep, AltSep}, 3)[0] & "/"
  blstPath = kzgPath & "blst/"
  srcPath  = kzgPath & "src/"
  bindingsPath = blstPath & "bindings"

when not defined(kzgExternalBlst):
  # Use default blst shipped with c-kzg-4844
  {.compile: blstPath & "build/assembly.S".}
  {.compile: blstPath & "src/server.c"}
  {.passc: "-D__BLST_PORTABLE__"}

{.compile: srcPath & "c_kzg_4844.c"}

{.passc: "-I" & escape(bindingsPath) .}
{.passc: "-I" & escape(srcPath) .}

const
  FIELD_ELEMENTS_PER_BLOB* = 4096
  BYTES_PER_FIELD_ELEMENT* = 32
  KzgBlobSize* = FIELD_ELEMENTS_PER_BLOB*BYTES_PER_FIELD_ELEMENT

type
  KZG_RET* = distinct cint

const
  # The common return type for all routines in which something can go wrong.
  KZG_OK*      = (0).KZG_RET
  KZG_BADARGS* = (1).KZG_RET
  KZG_ERROR*   = (2).KZG_RET
  KZG_MALLOC*  = (3).KZG_RET

func `$`*(x: KZG_RET): string =
  case x
  of KZG_OK: "ok"
  of KZG_BADARGS: "kzg badargs"
  of KZG_ERROR: "kzg error"
  of KZG_MALLOC: "kzg malloc error"
  else: "kzg unknown error"

func `==`*(a, b: KZG_RET): bool =
  a.cint == b.cint

type
  # Stores the setup and parameters needed for performing FFTs.
  CKzgSettings* {.importc: "KZGSettings",
    header: "c_kzg_4844.h", byref.} = object

  # A basic blob data.
  CKzgBlob* {.importc: "Blob",
    header: "c_kzg_4844.h".} = object
    bytes*: array[KzgBlobSize, uint8]

  # An array of 48 bytes. Represents an untrusted
  # (potentially invalid) commitment/proof.
  CKzgBytes48* {.importc: "Bytes48",
    header: "c_kzg_4844.h".} = object
    bytes*: array[48, uint8]

  # An array of 32 bytes. Represents an untrusted
  # (potentially invalid) field element.
  CKzgBytes32* {.importc: "Bytes32",
    header: "c_kzg_4844.h".} = object
    bytes*: array[32, uint8]

  # A trusted (valid) KZG commitment.
  CKzgCommitment* = CKzgBytes48

  # A trusted (valid) KZG proof.
  CKzgProof* = CKzgBytes48

{.pragma: kzg_abi, importc, cdecl, header: "c_kzg_4844.h".}

proc load_trusted_setup*(res: CKzgSettings,
                         g1Bytes: ptr byte, # n1 * 48 bytes
                         n1: csize_t,
                         g2Bytes: ptr byte, # n2 * 96 bytes
                         n2: csize_t): KZG_RET {.kzg_abi.}

proc load_trusted_setup_file*(res: CKzgSettings,
                         input: File): KZG_RET {.kzg_abi.}

proc free_trusted_setup*(s: CKzgSettings) {.kzg_abi.}

proc blob_to_kzg_commitment*(res: ptr CKzgCommitment,
                         blob: ptr CKzgBlob,
                         s: CKzgSettings): KZG_RET {.kzg_abi.}

proc compute_kzg_proof*(res: ptr CKzgProof,
                         yOut: ptr CKzgBytes32,
                         blob: ptr CKzgBlob,
                         zBytes: ptr CKzgBytes32,
                         s: CKzgSettings): KZG_RET {.kzg_abi.}

proc compute_blob_kzg_proof*(res: ptr CKzgProof,
                         blob: ptr CKzgBlob,
                         commitmentBytes: ptr CKzgBytes48,
                         s: CKzgSettings): KZG_RET {.kzg_abi.}

proc verify_kzg_proof*(res: var bool,
                         commitmentBytes: ptr CKzgBytes48,
                         zBytes: ptr CKzgBytes32,
                         yBytes: ptr CKzgBytes32,
                         proofBytes: ptr CKzgBytes48,
                         s: CKzgSettings): KZG_RET {.kzg_abi.}

proc verify_blob_kzg_proof*(res: var bool,
                         blob: ptr CKzgBlob,
                         commitmentsBytes: ptr CKzgBytes48,
                         proofBytes: ptr CKzgBytes48,
                         s: CKzgSettings): KZG_RET {.kzg_abi.}

proc verify_blob_kzg_proof_batch*(res: var bool,
                         blobs: ptr CKzgBlob,
                         commitmentsBytes: ptr CKzgBytes48,
                         proofBytes: ptr CKzgBytes48,
                         n: csize_t,
                         s: CKzgSettings): KZG_RET {.kzg_abi.}
