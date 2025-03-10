#!/bin/bash -eu

cargo fuzz build --release
for target in $(cargo fuzz list); do
    cp "fuzz/target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
done
