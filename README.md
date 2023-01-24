# C-KZG-4844: A minimal library for EIP-4844 Polynomial Commitments

This is a copy of [C-KZG](https://github.com/benjaminion/c-kzg) stripped-down to support the
[Polynomial Commitments](https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md) API:

- `blob_to_kzg_commitment`
- `compute_kzg_proof`
- `compute_aggregate_kzg_proof`
- `verify_kzg_proof`
- `verify_aggregate_kzg_proof`

We also provide functions for loading/freeing the trusted setup:

- `load_trusted_setup`
- `load_trusted_setup_file`
- `free_trusted_setup`

## Installation

Initialize the blst submodule:

```
git submodule update --init
```

Build blst:

```
cd src
make blst
```

Build the C-KZG code:

```
cd src
make
```
