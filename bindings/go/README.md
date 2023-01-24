# cgo-kzg-4844

This package implements Go bindings (using [Cgo](https://go.dev/blog/cgo)) for the
exported functions in [C-KZG-4844](https://github.com/ethereum/c-kzg-4844).

## Installation

```
go get github.com/ethereum/c-kzg-4844/bindings/go
```

## Go version

This package requires `1.19rc1` or later. Version `1.19beta1` and before will
not work. These versions have a linking issue and are unable to see `blst`
functions.

## Example

For example, a module with this source file:
```go
package main

import "fmt"
import "encoding/hex"
import ckzg "github.com/ethereum/c-kzg-4844/bindings/go"

func main() {
	ret := ckzg.LoadTrustedSetupFile("trusted_setup.txt")
	if ret != ckzg.C_KZG_OK {
		panic("failed to load trusted setup")
	}
	defer ckzg.FreeTrustedSetup()

	blob := ckzg.Blob{1, 2, 3}
	commitment, ret := ckzg.BlobToKZGCommitment(blob)
	if ret != ckzg.C_KZG_OK {
		panic("failed to get commitment for blob")
	}
	fmt.Println(hex.EncodeToString(commitment[:]))
}
```

Will produce this output:
```
$ go run .
88f1aea383b825371cb98acfbae6c81cce601a2e3129461c3c2b816409af8f3e5080db165fd327db687b3ed632153a62
```

The trusted setup file in the example can be downloaded here:
* https://github.com/ethereum/c-kzg-4844/raw/main/src/trusted_setup.txt

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