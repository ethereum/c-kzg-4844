# C-KZG-4844: A minimal library for EIP-4844 Polynomial Commitments

This is a copy of C-KZG stripped down to support the [Polynomial Commitments](https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md) API:

- `compute_aggregate_kzg_proof`
- `verify_aggregate_kzg_proof`
- `blob_to_kzg_commitment`
- `verify_kzg_proof`

We also provide `load_trusted_setup` and `free_trusted_setup` to load the
trusted setup data from a file into an object that can be passed to the API
functions, and functions for converting commitments/proofs/points to/from bytes.

## Installation

Install the blst submodule

```
git submodule update --init
```

Build blst

```
cd src
make blst
```

Build the C-KZG code

```
cd src
make
```
