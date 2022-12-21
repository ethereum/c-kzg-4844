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

## Problems

### Too many open files

If you encounter an issue like this:
```
warning: starting with empty corpus
fuzz: elapsed: 0s, execs: 0 (0/sec), new interesting: 0 (total: 0)
fuzz: elapsed: 1s, execs: 0 (0/sec), new interesting: 0 (total: 0)
--- FAIL: FuzzVerifyAggregateKzgProof (1.21s)
    open /dev/null: too many open files
FAIL
exit status 1
FAIL	fuzz	3.577s
```

Most likely, your system has a relatively low open file limit.
```
$ ulimit -n
1024
```

Raise that value by running the following command:
```
$ ulimit -n 100000
```

Now, try running the fuzzer again.