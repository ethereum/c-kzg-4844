// Run with the following command:
// cargo fuzz run fuzz_compute_cells_and_kzg_proofs

#![no_main]
extern crate core;

use c_kzg::Blob;
use c_kzg::KzgSettings;
use rust_eth_kzg::DASContext;
use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

lazy_static! {
    static ref KZG_SETTINGS: KzgSettings = {
        let root_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let trusted_setup_file = root_dir.join("..").join("src").join("trusted_setup.txt");
        KzgSettings::load_trusted_setup_file(&trusted_setup_file, 8).unwrap()
    };
    static ref DAS_CONTEXT: DASContext = DASContext::default();
}

fuzz_target!(|blob: Blob| {
    let ckzg_result = c_kzg::Cell::compute_cells_and_kzg_proofs(&blob, &KZG_SETTINGS);
    let rkzg_result = DAS_CONTEXT.compute_cells_and_kzg_proofs(&blob.into_inner());

    match (&ckzg_result, &rkzg_result) {
        (Ok((ckzg_cells, ckzg_proofs)), Ok((rkzg_cells, rkzg_proofs))) => {
            // Ensure the results are the same.
            for (ckzg_cell, rkzg_cell) in ckzg_cells.iter().zip(rkzg_cells.iter()) {
                assert_eq!(ckzg_cell.to_bytes().as_slice(), rkzg_cell.as_slice())
            }
            for (ckzg_proof, rkzg_proof) in ckzg_proofs.iter().zip(rkzg_proofs.iter()) {
                assert_eq!(ckzg_proof.as_slice(), rkzg_proof.as_slice())
            }
        }
        (Err(_), Err(_)) => {
            // Cannot compare errors, they are unique.
        }
        _ => {
            // There is a disagreement.
            panic!(
                "mismatch {:?} and {:?}",
                &ckzg_result.is_ok(),
                &rkzg_result.is_ok()
            );
        }
    }
});
