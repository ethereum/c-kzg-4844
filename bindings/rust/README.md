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

## Update `generated.rs`

```
cargo build --features generate-bindings
```
