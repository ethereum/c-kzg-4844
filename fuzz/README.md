# Fuzzing with Cgo

This uses [Cgo](https://go.dev/blog/cgo) (which lets Go packages call C code)
and [Go Fuzzing](https://go.dev/security/fuzz/) (Go's built in fuzzing tool) to
fuzz the exported KZG functions.

## Prerequisites

It's only necessary that you build BLST first.

```
cd ..
git submodule update --init
cd src
make blst
```

## Fuzzing

### `bytes_to_g1`
```
go test -fuzz=FuzzBytesToG1 .
```

### `bytes_from_g1`
```
go test -fuzz=FuzzBytesFromG1 .
```

### `bytes_to_bls_field`
```
go test -fuzz=FuzzBytesToBlsField .
```

### `compute_aggregate_kzg_proof`
```
go test -fuzz=FuzzComputeAggregateKzgProof .
```

### `verify_aggregate_kzg_proof`
```
go test -fuzz=FuzzVerifyAggregateKzgProof .
```

### `blob_to_kzg_commitment`
```
go test -fuzz=FuzzBlobToKzgCommitment .
```

### `verify_kzg_proof`
```
go test -fuzz=FuzzVerifyKzgProof .
```
