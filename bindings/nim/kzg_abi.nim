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

{.compile: srcPath & "ckzg.c"}

{.passc: "-I" & escape(bindingsPath) .}
{.passc: "-I" & escape(srcPath) .}

const
  FIELD_ELEMENTS_PER_BLOB* = 4096
  FIELD_ELEMENTS_PER_CELL* = 64
  BYTES_PER_FIELD_ELEMENT* = 32
  BYTES_PER_BLOB* = FIELD_ELEMENTS_PER_BLOB*BYTES_PER_FIELD_ELEMENT
  BYTES_PER_CELL* = FIELD_ELEMENTS_PER_CELL*BYTES_PER_FIELD_ELEMENT
  CELLS_PER_EXT_BLOB* = 128

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
  KzgSettings* {.importc: "KZGSettings",
    header: "ckzg.h", byref.} = object

  # A basic blob data.
  KzgBlob* {.importc: "Blob",
    header: "ckzg.h", completeStruct.} = object
    bytes*: array[BYTES_PER_BLOB, uint8]

  # An array of 48 bytes. Represents an untrusted
  # (potentially invalid) commitment/proof.
  KzgBytes48* {.importc: "Bytes48",
    header: "ckzg.h", completeStruct.} = object
    bytes*: array[48, uint8]

  # An array of 32 bytes. Represents an untrusted
  # (potentially invalid) field element.
  KzgBytes32* {.importc: "Bytes32",
    header: "ckzg.h", completeStruct.} = object
    bytes*: array[32, uint8]

  # A trusted (valid) KZG commitment.
  KzgCommitment* = KzgBytes48

  # A trusted (valid) KZG proof.
  KzgProof* = KzgBytes48

  # A single cell for a blob.
  KzgCell* {.importc: "Cell",
    header: "ckzg.h", completeStruct.} = object
    bytes*: array[BYTES_PER_CELL, uint8]

{.pragma: kzg_abi, importc, cdecl, header: "ckzg.h".}

proc load_trusted_setup*(res: ptr KzgSettings,
                         g1MonomialBytes: ptr byte,
                         numG1MonomialBytes: uint64,
                         g1LagrangeBytes: ptr byte,
                         numG1LagrangeBytes: uint64,
                         g2MonomialBytes: ptr byte,
                         numG2MonomialBytes: uint64,
                         precompute: uint64): KZG_RET {.kzg_abi.}

proc load_trusted_setup_file*(res: ptr KzgSettings,
                         input: File,
                         precompute: uint64): KZG_RET {.kzg_abi.}

proc free_trusted_setup*(s: ptr KzgSettings) {.kzg_abi.}

proc blob_to_kzg_commitment*(res: var KzgCommitment,
                         blob: ptr KzgBlob,
                         s: ptr KzgSettings): KZG_RET {.kzg_abi.}

proc compute_kzg_proof*(res: var KzgProof,
                         yOut: var KzgBytes32,
                         blob: ptr KzgBlob,
                         zBytes: ptr KzgBytes32,
                         s: ptr KzgSettings): KZG_RET {.kzg_abi.}

proc compute_blob_kzg_proof*(res: var KzgProof,
                         blob: ptr KzgBlob,
                         commitmentBytes: ptr KzgBytes48,
                         s: ptr KzgSettings): KZG_RET {.kzg_abi.}

proc verify_kzg_proof*(res: var bool,
                         commitmentBytes: ptr KzgBytes48,
                         zBytes: ptr KzgBytes32,
                         yBytes: ptr KzgBytes32,
                         proofBytes: ptr KzgBytes48,
                         s: ptr KzgSettings): KZG_RET {.kzg_abi.}

proc verify_blob_kzg_proof*(res: var bool,
                         blob: ptr KzgBlob,
                         commitmentsBytes: ptr KzgBytes48,
                         proofBytes: ptr KzgBytes48,
                         s: ptr KzgSettings): KZG_RET {.kzg_abi.}

proc verify_blob_kzg_proof_batch*(res: var bool,
                         blobs: ptr KzgBlob,
                         commitmentsBytes: ptr KzgBytes48,
                         proofBytes: ptr KzgBytes48,
                         n: uint64,
                         s: ptr KzgSettings): KZG_RET {.kzg_abi.}

proc compute_cells*(cellsOut: ptr KzgCell,
                         blob: ptr KzgBlob,
                         s: ptr KzgSettings): KZG_RET {.kzg_abi.}

proc compute_cells_and_kzg_proofs*(cellsOut: ptr KzgCell,
                         proofsOut: ptr KzgProof,
                         blob: ptr KzgBlob,
                         s: ptr KzgSettings): KZG_RET {.kzg_abi.}

proc recover_cells_and_kzg_proofs*(recoveredOut: ptr KzgCell,
                         recoveredProofsOut: ptr KzgProof,
                         cellIndices: ptr uint64,
                         cells: ptr KzgCell,
                         numCells: uint64,
                         s: ptr KzgSettings): KZG_RET {.kzg_abi.}

proc verify_cell_kzg_proof_batch*(res: var bool,
                         commitments: ptr KzgBytes48,
                         cellIndices: ptr uint64,
                         cells: ptr KzgCell,
                         proofs: ptr KzgBytes48,
                         numCells: uint64,
                         s: ptr KzgSettings): KZG_RET {.kzg_abi.}
