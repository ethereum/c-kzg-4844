# C-KZG-4844

A minimal implementation of the [Polynomial
Commitments](https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md)
API for EIP-4844, written in C.

## Bindings

While the core implementation is in C, bindings are available for various
high-level languages, providing convenient wrappers around C functions. These
bindings are intended to be used by Ethereum clients, to avoid re-implementation
of crucial cryptographic functions.

| Language | Link                                 |
|----------|--------------------------------------|
| C#       | [README](bindings/csharp/README.md)  |
| Go       | [README](bindings/go/README.md)      |
| Java     | [README](bindings/java/README.md)    |
| Nim      | [README](bindings/nim/README.md)     |
| Node.js  | [README](bindings/node.js/README.md) |
| Python   | [README](bindings/python/README.md)  |
| Rust     | [README](bindings/rust/README.md)    |

## Interface functions

The C-KZG-4844 library provides implementations of the public KZG functions that
are defined in the Polynomial Commitments specification. The aim is to align
these functions as closely as possible with the specification.

- `blob_to_kzg_commitment`
- `compute_kzg_proof`
- `compute_blob_kzg_proof`
- `verify_kzg_proof`
- `verify_blob_kzg_proof`
- `verify_blob_kzg_proof_batch`

This library also provides functions for loading and freeing the trusted setup,
which are not defined in the specification. These functions are intended to be
executed once during the initialization process. As the name suggests, the
[trusted setup
file](https://github.com/ethereum/c-kzg-4844/blob/main/src/trusted_setup.txt) is
considered to be trustworthy.

- `load_trusted_setup`
- `load_trusted_setup_file`
- `free_trusted_setup`

## Remarks

### Tests

All the bindings are tested against the [KZG reference
tests](https://github.com/ethereum/consensus-spec-tests/tree/master/tests/general/deneb/kzg),
which are defined in the consensus-spec-tests. Additionally, a suite of unit
tests for internal C functions is located
[here](https://github.com/ethereum/c-kzg-4844/blob/main/src/test_c_kzg_4844.c).

### Parallelization

The interface functions in C-KZG-4844 are single-threaded for simplicity, as
implementing multi-threading across multiple platforms can be complex. While
performance is important, these functions are already quite fast and efficient.
For instance, `verify_blob_kzg_proof` is expected to finish in under 3ms on most
systems.

### Batched verification

When processing multiple blobs, `verify_blob_kzg_proof_batch` is more efficient
than calling `verify_blob_kzg_proof` individually. In CI tests, verifying 64
blobs in batch is 53% faster per blob than verifying them individually. For a
single blob, `verify_blob_kzg_proof_batch` calls `verify_blob_kzg_proof`, and
the overhead is negligible.

### Benchmarks

C-KZG-4844 does not include C benchmarks; however, some bindings (Go, Java, and
Rust) have their own benchmarks. Including benchmarks in the bindings offers a
more realistic performance estimate, as C-KZG-4844 is not expected to be used
outside the bindings.

### Security audit

The source code of C-KZG-4844 was audited by [Sigma
Prime](https://sigmaprime.io/) in June 2023. You can find the [audit
report](https://github.com/ethereum/c-kzg-4844/blob/main/doc/audit/Sigma_Prime_Ethereum_Foundation_KZG_Implementations_Security_Assessment.pdf)
in the `doc/audit/` directory.

### Why C?

The primary reason for choosing C is that
[blst](https://github.com/supranational/blst), the BLS12-381 signature library
we wanted to use, is mostly written in C. Rust was a viable alternative, but it
has some disadvantages. The C toolchain is ubiquitous, and it would be somewhat
awkward for all the bindings to depend on another toolchain, such as Rust.
Compared to Rust, C offers a lighter memory and binary footprint. Furthermore, C
serves as the de facto language for
[FFI](https://en.wikipedia.org/wiki/Foreign_function_interface), so we could not
have completely avoided using C anyway.
