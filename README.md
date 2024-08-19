# C-KZG-4844

A minimal implementation of the Polynomial Commitments API for
[EIP-4844](https://eips.ethereum.org/EIPS/eip-4844) and
[EIP-7594](https://eips.ethereum.org/EIPS/eip-7594), written in C.

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

For EIP-4844:

- `blob_to_kzg_commitment`
- `compute_kzg_proof`
- `compute_blob_kzg_proof`
- `verify_kzg_proof`
- `verify_blob_kzg_proof`
- `verify_blob_kzg_proof_batch`

For EIP-7594:

- `compute_cells_and_kzg_proofs`
- `recover_cells_and_kzg_proofs`
- `verify_cell_kzg_proof_batch`

This library also provides functions for loading and freeing the trusted setup,
which are not defined in the specification. These functions are intended to be
executed once during the initialization process. As the name suggests, the
[trusted setup file](src/trusted_setup.txt) is considered to be trustworthy.

- `load_trusted_setup`
- `load_trusted_setup_file`
- `free_trusted_setup`

## Remarks

### Tests

All bindings are tested against the KZG reference tests, which are defined in
the [consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests)
repository. Additionally, a suite of unit tests for internal C functions is
located [here](src/test/tests.c).

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

C-KZG-4844 provides benchmarks in the Go bindings. It is easier to write
benchmarks in a high-level language and doing benchmarks in the bindings offers
a more realistic performance overview, including FFI overhead. Additionally,
C-KZG-4844 is not expected to be used outside the bindings.

### Security audit

The source code of C-KZG-4844 was audited by [Sigma
Prime](https://sigmaprime.io/) in June 2023. You can find the [audit
report](doc/audit/Sigma_Prime_Ethereum_Foundation_KZG_Implementations_Security_Assessment.pdf)
in the `doc/audit/` directory. Notably, the audit was for commit `fd24cf8` and 
code introduced for EIP-7594 *has not been audited yet*. 

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
