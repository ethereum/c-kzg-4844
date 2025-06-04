// Run with the following command:
// cargo fuzz run fuzz_recover_cells_and_kzg_proofs

#![no_main]
extern crate core;

use arbitrary::Arbitrary;
use c_kzg::Cell;
use c_kzg::KzgSettings;
use c_kzg::BYTES_PER_CELL;
use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use rust_eth_kzg::DASContext;
use std::env;
use std::path::PathBuf;

///////////////////////////////////////////////////////////////////////////////
// Helper Functions
///////////////////////////////////////////////////////////////////////////////

fn get_root_dir() -> PathBuf {
    if let Ok(manifest) = env::var("CARGO_MANIFEST_DIR") {
        // When running locally
        PathBuf::from(manifest)
            .parent()
            .expect("CARGO_MANIFEST_DIR has no parent")
            .to_path_buf()
    } else {
        // When running with oss-fuzz
        env::current_dir().expect("Failed to get current directory")
    }
}

///////////////////////////////////////////////////////////////////////////////
// Initialization
///////////////////////////////////////////////////////////////////////////////

lazy_static! {
    static ref KZG_SETTINGS: KzgSettings = {
        let trusted_setup_file = get_root_dir().join("src").join("trusted_setup.txt");
        KzgSettings::load_trusted_setup_file(&trusted_setup_file, 0).unwrap()
    };
    static ref DAS_CONTEXT: DASContext = DASContext::default();
}

///////////////////////////////////////////////////////////////////////////////
// Fuzz Target
///////////////////////////////////////////////////////////////////////////////

#[derive(Arbitrary, Debug)]
struct Input {
    cell_indices: Vec<u64>,
    cells: Vec<Cell>,
}

fuzz_target!(|input: Input| {
    let cells_bytes_owned: Vec<[u8; BYTES_PER_CELL]> =
        input.cells.iter().map(Cell::to_bytes).collect();
    let cells_bytes: Vec<&[u8; BYTES_PER_CELL]> = cells_bytes_owned.iter().collect();

    let ckzg_result = KZG_SETTINGS
        .recover_cells_and_kzg_proofs(input.cell_indices.as_slice(), input.cells.as_slice());
    let rkzg_result = DAS_CONTEXT.recover_cells_and_kzg_proofs(input.cell_indices, cells_bytes);

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
                "mismatch: {:?}, {:?}",
                &ckzg_result.is_ok(),
                &rkzg_result.is_ok()
            );
        }
    }
});
