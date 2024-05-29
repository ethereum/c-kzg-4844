// Run with the following command:
// cargo fuzz run fuzz_compute_cells --fuzz-dir rustfuzz

#![no_main]
use libfuzzer_sys::fuzz_target;
use lazy_static::lazy_static;
use std::path::PathBuf;
use c_kzg::KzgSettings;
use c_kzg::Blob;

lazy_static! {
    static ref KZG_SETTINGS: KzgSettings = {
        let root_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let trusted_setup_file = root_dir.join("..").join("src").join("trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        KzgSettings::load_trusted_setup_file(&trusted_setup_file, 0).unwrap()
    };
}

fuzz_target!(|blob: Blob| {
    let kzg_settings = &*KZG_SETTINGS;
    let _ = c_kzg::Cell::compute_cells(&blob, kzg_settings);
});