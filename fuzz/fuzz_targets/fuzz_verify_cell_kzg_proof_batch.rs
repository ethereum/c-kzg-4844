// Run with the following command:
// cargo fuzz run fuzz_verify_cell_kzg_proof_batch

#![no_main]
extern crate core;

use arbitrary::Arbitrary;
use c_kzg::KzgSettings;
use c_kzg::BYTES_PER_CELL;
use c_kzg::BYTES_PER_COMMITMENT;
use c_kzg::BYTES_PER_PROOF;
use c_kzg::{Bytes48, Cell};
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
    static ref VERIFIER_CONTEXT: VerifierContext = VerifierContext::default();
}

#[derive(Arbitrary, Debug)]
struct Input {
    row_commitments: Vec<Bytes48>,
    row_indices: Vec<u64>,
    column_indices: Vec<u64>,
    cells: Vec<Cell>,
    proofs: Vec<Bytes48>,
}

fuzz_target!(|input: Input| {
    let cells_bytes_owned: Vec<[u8; BYTES_PER_CELL]> =
        input.cells.iter().map(Cell::to_bytes).collect();
    let cells_bytes: Vec<&[u8; BYTES_PER_CELL]> = cells_bytes_owned.iter().collect();

    let commitments_owned: Vec<[u8; BYTES_PER_COMMITMENT]> = input
        .row_commitments
        .iter()
        .map(|c| Bytes48::into_inner(*c))
        .collect();
    let commitments_bytes: Vec<&[u8; BYTES_PER_COMMITMENT]> = commitments_owned.iter().collect();

    let proofs_owned: Vec<[u8; BYTES_PER_PROOF]> = input
        .proofs
        .iter()
        .map(|p| Bytes48::into_inner(*p))
        .collect();
    let proofs_bytes: Vec<&[u8; BYTES_PER_PROOF]> = proofs_owned.iter().collect();

    let ckzg_result = c_kzg::KzgProof::verify_cell_kzg_proof_batch(
        &input.row_commitments,
        &input.row_indices,
        &input.column_indices,
        &input.cells,
        &input.proofs,
        &KZG_SETTINGS,
    );
    let rkzg_result = VERIFIER_CONTEXT.verify_cell_kzg_proof_batch(
        commitments_bytes,
        input.row_indices,
        input.column_indices,
        cells_bytes,
        proofs_bytes,
    );

    match (&ckzg_result, &rkzg_result) {
        (Ok(ckzg_valid), Ok(())) => {
            // One returns a boolean, the other just says Ok.
            assert_eq!(*ckzg_valid, true);
        }
        (Ok(ckzg_valid), Err(err)) => {
            // If ckzg was Ok, ensure the proof was rejected.
            assert_eq!(*ckzg_valid, false);
            match err {
                eip7594::verifier::VerifierError::InvalidProof => (),
                _ => panic!("Expected InvalidProof, got {:?}", err),
            }
        }
        (Err(_), Err(_)) => {
            // Cannot compare errors, they are unique.
        }
        _ => {
            // There is a disagreement.
            panic!("mismatch {:?} and {:?}", &ckzg_result, &rkzg_result);
        }
    }
});
