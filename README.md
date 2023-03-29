# C-KZG-4844

A minimal implemention of the [Polynomial
Commitments](https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md)
API for EIP-4844, written in C.

Bindings are available for the following languages:

| Language | Link                                 | Package Reference                                 |
|----------|--------------------------------------|---------------------------------------------------|
| C#       | [README](bindings/csharp/README.md)  | https://www.nuget.org/packages/Ckzg.Bindings      |
| Go       | [README](bindings/go/README.md)      | https://pkg.go.dev/github.com/ethereum/c-kzg-4844 |
| Java     | [README](bindings/java/README.md)    | https://github.com/ConsenSys/jc-kzg-4844          |
| Nim      | [README](bindings/nim/README.md)     |                                                   |
| Node.js  | [README](bindings/node.js/README.md) | https://www.npmjs.com/package/c-kzg               |
| Python   | [README](bindings/python/README.md)  | (for internal testing only)                       |
| Rust     | [README](bindings/rust/README.md)    |                                                   |

## Interface functions

The C-KZG-4844 library provides an implementation of the KZG functions specified
as public in the Polynomial Commitments specification. The aim is to align these
functions as closely as possible with the specification.

- `blob_to_kzg_commitment`
- `compute_kzg_proof`
- `compute_blob_kzg_proof`
- `verify_kzg_proof`
- `verify_blob_kzg_proof`
- `verify_blob_kzg_proof_batch`

This library also provides functions for loading and freeing the trusted setup,
which are not specified in the specification. These functions are intended to be
executed once during the initialization process. As the name suggests, the
[trusted setup
file](https://github.com/ethereum/c-kzg-4844/blob/main/src/trusted_setup.txt) is
considered to be trustworthy.

- `load_trusted_setup`
- `load_trusted_setup_file`
- `free_trusted_setup`

## Remarks

### Tests

All the bindings are tested against the [KZG reference tests defined in the
consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests/tree/master/tests/general/deneb/kzg).
Additionally, a suite of custom unit tests for the C functions is located
[here](https://github.com/ethereum/c-kzg-4844/blob/main/src/test_c_kzg_4844.c),
which tests the specific functionality of internal functions.

### Parallelization

The interface functions in C-KZG-4844 are single-threaded for simplicity, as
implementing multi-threading across multiple platforms can be complex. While
performance is important, these functions are already quite fast/efficient. For
instance, `verify_blob_kzg_proof` is expected to finish in under three
milliseconds on most systems.

### Batched verification

For processing multiple blobs, `verify_blob_kzg_proof_batch` is more efficient
than calling `verify_blob_kzg_proof` individually. In CI tests, verifying 64
blobs in batch is 53% faster per blob than verifying them individually. For a
single blob, `verify_blob_kzg_proof_batch` calls `verify_blob_kzg_proof`, and
the overhead is negligible.

### Benchmarks

C-KZG-4844 does not include C benchmarks; however, some bindings (Go, Java, and
Rust) have their own benchmarks. Including benchmarks in the bindings offers a
more realistic performance estimate, as C-KZG-4844 is not expected to be used
outside of the bindings.

### Why C?

The primary reason for choosing C is because
[blst](https://github.com/supranational/blst), the BLS12-381 signature library
we wanted to use, is mostly written in C. Creating bindings to C functions for
all the higher-level languages we wanted is relatively straightforward and
well-documented. We were concerned that using blst with another language, like
Rust, and then building bindings on top of it would introduce too much overhead.
Furthermore, the C toolchain is ubiquitous, and it would be somewhat awkward for
all the bindings to depdend on another toolchain, like Rust.
