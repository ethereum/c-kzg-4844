# Zig Bindings for the C-KZG Library

This directory contains Zig bindings for the C-KZG-4844 library.

## Prerequisites

Use Zig `0.17.0` or greater.

## Build

```sh
zig build -Doptimize=ReleaseSafe
```

## Test

Convert tests from YAML to JSON (requires [`yq`](https://github.com/mikefarah/yq)):

```sh
find tests -name "data.yaml" -exec sh -c 'yq -o=json "$1" > "$(dirname "$1")/data.json"' _ {} \;
```

Then run:

```sh
zig build test
```

## Usage

From the root of your Zig project:

```sh
zig fetch --save=ckzg https://github.com/ethereum/c-kzg-4844/archive/<commit>.tar.gz
```

Then wire the `ckzg` module into `build.zig`:

```zig
const ckzg_dep = b.dependency("ckzg", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("ckzg", ckzg_dep.module("ckzg"));
```

Then import and initialize:

```zig
const ckzg = @import("ckzg");

var settings = try ckzg.Settings.loadTrustedSetupFile("/path/to/trusted_setup.txt", 0);
defer settings.deinit();
```
