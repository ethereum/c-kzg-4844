#!/bin/bash -eu

cd "$SRC/c-kzg-4844"

echo "Copying the trusted setup"
mkdir -p "$OUT/src" && cp src/trusted_setup.txt "$OUT/src/"

echo "Generating seed corpuses"
cargo test --features generate-fuzz-corpus
for target in $(cargo fuzz list); do
    pushd fuzz/corpus/$target
    echo "Zipping seed corpus for $target"
    zip -r "$OUT/${target}_seed_corpus.zip" .
    popd
done

echo "Building fuzz targets"
cargo fuzz build --release
for target in $(cargo fuzz list); do
    cp "fuzz/target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
done
