// Run with the following command:
// cargo fuzz run fuzz_verify_blob_kzg_proof_batch

#![no_main]
extern crate core;

use arbitrary::Arbitrary;
use c_kzg::{Blob, Bytes48, KzgSettings};
use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

lazy_static! {
    static ref KZG_SETTINGS: KzgSettings = {
        let root_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let trusted_setup_file = root_dir.join("..").join("src").join("trusted_setup.txt");
        KzgSettings::load_trusted_setup_file(&trusted_setup_file, 0).unwrap()
    };
}

#[derive(Arbitrary, Debug)]
struct Input {
    blobs: Vec<Blob>,
    commitments: Vec<Bytes48>,
    proofs: Vec<Bytes48>,
}

fuzz_target!(|input: Input| {
    let _ckzg_result = c_kzg::KzgProof::verify_blob_kzg_proof_batch(
        &input.blobs,
        &input.commitments,
        &input.proofs,
        &KZG_SETTINGS,
    );
});
