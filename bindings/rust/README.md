# Rust bindings

Generates the rust bindings for the c-kzg library. 

## Build

```
cargo build --release
```

## Test

```
cargo test --release
```

## Benchmark

```
cargo bench
```

## Update `generated.rs`

```
cargo build --features generate-bindings
```
