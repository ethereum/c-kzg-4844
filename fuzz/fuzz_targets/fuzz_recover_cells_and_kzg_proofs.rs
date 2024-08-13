// Run with the following command:
// cargo fuzz run fuzz_recover_cells_and_kzg_proofs

#![no_main]
extern crate core;

use arbitrary::Arbitrary;
use c_kzg::Cell;
use c_kzg::KZGSettings;
use c_kzg::BYTES_PER_CELL;
use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use rust_eth_kzg::DASContext;
use std::path::PathBuf;

lazy_static! {
    static ref KZG_SETTINGS: KZGSettings = {
        let root_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let trusted_setup_file = root_dir.join("..").join("src").join("trusted_setup.txt");
        KZGSettings::load_trusted_setup_file(&trusted_setup_file, 0).unwrap()
    };
    static ref DAS_CONTEXT: DASContext = DASContext::default();
}

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
    let rkzg_result = DAS_CONTEXT.recover_cells_and_proofs(input.cell_indices, cells_bytes);

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
