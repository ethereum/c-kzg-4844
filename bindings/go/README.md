# Go Bindings for C-KZG-4844

## Prerequisites

It's only necessary that you build BLST first.

```
cd ../../
git submodule update --init
cd src
make blst
```

## Fuzzing

This uses [Cgo](https://go.dev/blog/cgo) (which lets Go packages call C code)
and [Go Fuzzing](https://go.dev/security/fuzz/) (Go's built in fuzzing tool) to
fuzz the exported KZG functions.

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

### Problems

#### Cannot use (*a*) as type (*b*) in variable declaration

If you encounter an issue like this:
```
./main.go:136:9: cannot use (*_Ctype_Blob)(unsafe.Pointer(&blobs)) (value of type *_Ctype_Blob) as type *[131072]_Ctype_uchar in variable declaration
./main.go:158:9: cannot use (*_Ctype_Blob)(unsafe.Pointer(&blobs)) (value of type *_Ctype_Blob) as type *[131072]_Ctype_uchar in variable declaration
```

Most likely, your system is defaulting to `gcc` as the compiler. We use `clang` instead.

To fix this, install `clang` and prepend `CC=clang` to the command, like:
```
CC=clang go test -fuzz=FuzzBytesToG1 .
```

#### Too many open files

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

### Notes

* We use `TypeProvider#getNBytes` instead of `TypeProvider#Fill` because it's ~10 times faster.
  * This requires we `copy` the bytes, but it's still that much faster.
* For generating blobs, we use `bytes#Repeat` because it's rare to get 131,072+ bytes for fuzzing.
  * It would be nice to ask for that many random bytes and actually get it.
* When generating multiple blobs/commitments, we generate until we run out of bytes.
  * If we get a random `count` and try to generate that many, it will almost always fail.
