# Zig Bindings for C-KZG-4844

Zig bindings for the C-KZG-4844 library, providing polynomial commitments for EIP-4844 and EIP-7594.

## Prerequisites

- Zig 0.14.0 or later

## Installation

### Using zig fetch

```bash
zig fetch https://github.com/ethereum/c-kzg-4844
```

The build system will automatically download the blst library when needed.

### Manual dependency

Add this as a dependency in your `build.zig.zon`:

```zig
.dependencies = .{
    .c_kzg_4844 = .{
        .url = "https://github.com/ethereum/c-kzg-4844/archive/main.tar.gz",
        .hash = "...", // zig will fill this in
    },
},
```

## Usage

### Basic Usage

```zig
const kzg = @import("c_kzg_4844");

// Load trusted setup from file
try kzg.loadTrustedSetupFile("trusted_setup.txt", 0);
defer kzg.freeTrustedSetup();

// Create a blob and compute commitment
var blob: kzg.Blob = undefined;
// ... fill blob with data ...

const commitment = try kzg.blobToKZGCommitment(&blob);
const proof = try kzg.computeBlobKZGProof(&blob, &commitment);
const is_valid = try kzg.verifyBlobKZGProof(&blob, &commitment, &proof);
```

### Using Embedded Trusted Setup

```zig
const kzg = @import("c_kzg_4844");

// Load embedded trusted setup (includes ~807KB in binary)
try kzg.loadTrustedSetupFromText(kzg.embedded_trusted_setup, 0);
defer kzg.freeTrustedSetup();

// Use KZG functions as normal...
```

### Dead Code Elimination

The embedded trusted setup is only included when explicitly referenced:

```zig
// No embedded data included (dead code eliminated)
try kzg.loadTrustedSetupFile("setup.txt", 0);

// Embedded data included only when used
try kzg.loadTrustedSetupFromText(kzg.embedded_trusted_setup, 0);
```

## API Reference

### Loading Trusted Setup

- `loadTrustedSetup(g1_monomial, g1_lagrange, g2_monomial, precompute)` - Load from raw bytes
- `loadTrustedSetupFromText(text, precompute)` - Load from text format
- `loadTrustedSetupFile(path, precompute)` - Load from file
- `freeTrustedSetup()` - Free loaded setup

### KZG Operations

- `blobToKZGCommitment(blob)` - Convert blob to commitment
- `computeKZGProof(blob, z)` - Compute proof at evaluation point
- `verifyKZGProof(commitment, z, y, proof)` - Verify proof
- `computeBlobKZGProof(blob, commitment)` - Compute blob proof
- `verifyBlobKZGProof(blob, commitment, proof)` - Verify blob proof

### Constants

- `embedded_trusted_setup` - Embedded trusted setup data
- `BYTES_PER_BLOB`, `BYTES_PER_COMMITMENT`, etc. - Size constants

### Types

- `Blob` - 131072 byte blob data
- `KZGCommitment` - 48 byte commitment
- `KZGProof` - 48 byte proof
- `Bytes32`, `Bytes48` - Fixed-size byte arrays
- `KZGError` - Error union for operations

## Building

```bash
zig build
zig build test
```

## License

Same as the parent C-KZG-4844 library.