// Run with the following command:
// cargo fuzz run fuzz_recover_all_cells --fuzz-dir rustfuzz

#![no_main]
extern crate core;

use arbitrary::Arbitrary;
use c_kzg::Bytes48;
use c_kzg::Cell;
use c_kzg::KzgSettings;
use eip7594::constants::BYTES_PER_CELL;
use eip7594::verifier::VerifierContext;
use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

lazy_static! {
    static ref KZG_SETTINGS: KzgSettings = {
        let root_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let trusted_setup_file = root_dir.join("..").join("src").join("trusted_setup.txt");
        KzgSettings::load_trusted_setup_file(&trusted_setup_file, 0).unwrap()
    };
    static ref VERIFIER_CONTEXT: VerifierContext = VerifierContext::new();
}

#[derive(Arbitrary, Debug)]
struct Input {
    cell_ids: Vec<u64>,
    cells: Vec<Cell>,
    proofs: Vec<Bytes48>,
}

fuzz_target!(|input: Input| {
    let cell_bytes: Vec<[u8; BYTES_PER_CELL]> = input.cells.iter().map(Cell::to_bytes).collect();
    let cell_slices: Vec<&[u8]> = cell_bytes.iter().map(|b| b.as_slice()).collect();

    let ckzg_result = c_kzg::Cell::recover_cells_and_kzg_proofs(
        input.cell_ids.as_slice(),
        input.cells.as_slice(),
        input.proofs.as_slice(),
        &KZG_SETTINGS,
    );
    let rkzg_result = VERIFIER_CONTEXT.recover_all_cells(input.cell_ids, cell_slices);

    match (&ckzg_result, &rkzg_result) {
        /* TODO: Compare proofs when peerdas-kzg updates */
        (Ok((ckzg_cells, _ckzg_proofs)), Ok(rkzg_cells)) => {
            // Ensure the results are the same.
            for (ckzg_cell, rkzg_cell) in ckzg_cells.iter().zip(rkzg_cells.iter()) {
                assert_eq!(ckzg_cell.to_bytes().as_slice(), rkzg_cell.as_slice())
            }
            /*
            for (ckzg_proof, rkzg_proof) in ckzg_proofs.iter().zip(rkzg_proofs.iter()) {
                assert_eq!(ckzg_proof.as_slice(), rkzg_proof.as_slice())
            }
            */
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
