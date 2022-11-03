# C-KZG-4844: A minimal library for EIP-4844 Polynomial Commitments

This is a copy of C-KZG stripped down to support the [Polynomial Commitments](https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/polynomial-commitments.md) API:
- `compute_aggregate_kzg_proof`
- `verify_aggregate_kzg_proof`
- `blob_to_kzg_commitment`
- `verify_kzg_proof`

We also provide `load_trusted_setup` and `free_trusted_setup` to load the
trusted setup data from a file into an object that can be passed to the API
functions.

The only dependency is [blst](https://github.com/supranational/blst).
Ensure `blst.h` is provided in `inc` and `libblst.a` in `lib`.
(`blst.h` includes `blst_aux.h`, but the latter is unused and can be empty.)
TODO: import these via git submodule
