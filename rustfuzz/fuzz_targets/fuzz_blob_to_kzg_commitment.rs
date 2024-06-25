// Run with the following command:
// cargo fuzz run fuzz_blob_to_kzg_commitment --fuzz-dir rustfuzz

#![no_main]
extern crate core;

use c_kzg::{Blob, KzgSettings};
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

fuzz_target!(|blob: Blob| {
    let _ckzg_result = c_kzg::KzgCommitment::blob_to_kzg_commitment(&blob, &KZG_SETTINGS);
});
