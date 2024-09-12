# Rust Bindings for the C-KZG Library

This directory contains Rust bindings for the C-KZG-4844 library.

## Prerequisites

Make sure you have `cargo` and `rust` installed.
You can do so with [`rustup`](https://rustup.rs):

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

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
