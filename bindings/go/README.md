# Go bindings

This package implements Go bindings (using [Cgo](https://go.dev/blog/cgo)) for the
exported functions in [C-KZG-4844](https://github.com/ethereum/c-kzg-4844).

## Installation

```
go get github.com/ethereum/c-kzg-4844
```

## Go version

This package requires `1.19rc1` or later. Version `1.19beta1` and before will
not work. These versions have a linking issue and are unable to see `blst`
functions.

## Example

For reference, see the `example` module in this directory. You can test it out with `go run`:

```
user@system ~/c-kzg-4844/bindings/go/example $ go run .
go: downloading github.com/ethereum/c-kzg-4844 v0.0.0-20230407130613-fd0a51aa35bc
go: downloading github.com/supranational/blst v0.3.11-0.20230406105308-e9dfc5ee724b
88f1aea383b825371cb98acfbae6c81cce601a2e3129461c3c2b816409af8f3e5080db165fd327db687b3ed632153a62
```

## Tests

Run the tests with this command:
```
go test
```

## Benchmarks

Run the benchmarks with this command:
```
go test -bench=Benchmark
```

## Minimal

By default, `FIELD_ELEMENTS_PER_BLOB` will be 4096 (mainnet), but you can
manually set it to 4 (minimal), like so:
```
CGO_CFLAGS="-DFIELD_ELEMENTS_PER_BLOB=4" go build
```

## Note

The `go.mod` and `go.sum` files are in the project's root directory because the
bindings need access to the c-kzg-4844 source, but Go cannot reference files
outside its module/package. The best way to deal with this is to make the whole
project available, that way everything is accessible.
