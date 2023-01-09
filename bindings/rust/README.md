# Rust bindings

Generates the rust bindings for the c-kzg library. 

## Build

```
cargo build --release
```

Build with `--features="minimal-spec"` to set the `FIELD_ELEMENTS_PER_BLOB` compile time parameter to the pre-determined minimal spec value. 

## Test

```
cargo test --release
```

## Benchmark

```
cargo bench
```
