// Run with the following command:
// cargo fuzz run fuzz_verify_blob_kzg_proof_batch

#![no_main]
extern crate core;

use arbitrary::Arbitrary;
use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use std::cell::UnsafeCell;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

///////////////////////////////////////////////////////////////////////////////
// CKZG Initialization
///////////////////////////////////////////////////////////////////////////////

lazy_static! {
    static ref KZG_SETTINGS: c_kzg::KZGSettings = {
        let root_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let trusted_setup_file = root_dir.join("..").join("src").join("trusted_setup.txt");
        c_kzg::KZGSettings::load_trusted_setup_file(&trusted_setup_file, 0).unwrap()
    };
}

///////////////////////////////////////////////////////////////////////////////
// Constantine Initialization
///////////////////////////////////////////////////////////////////////////////

struct SafeEthKzgContext {
    inner: UnsafeCell<constantine::EthKzgContext<'static>>,
}

unsafe impl Send for SafeEthKzgContext {}
unsafe impl Sync for SafeEthKzgContext {}

impl SafeEthKzgContext {
    fn new(ctx: constantine::EthKzgContext<'static>) -> Self {
        SafeEthKzgContext {
            inner: UnsafeCell::new(ctx),
        }
    }
    fn get(&self) -> &constantine::EthKzgContext<'static> {
        unsafe { &*self.inner.get() }
    }
}

static CONSTANTINE_CTX: OnceLock<Arc<SafeEthKzgContext>> = OnceLock::new();

fn initialize_constantine_ctx() -> Arc<SafeEthKzgContext> {
    let root_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let trusted_setup_file = root_dir.join("..").join("src").join("trusted_setup.txt");
    let eth_kzg_context =
        constantine::EthKzgContext::load_trusted_setup(&trusted_setup_file).unwrap();
    Arc::new(SafeEthKzgContext::new(eth_kzg_context))
}

///////////////////////////////////////////////////////////////////////////////
// Fuzz Target
///////////////////////////////////////////////////////////////////////////////

#[derive(Arbitrary, Debug)]
struct Input {
    blobs: Vec<c_kzg::Blob>,
    commitments: Vec<c_kzg::Bytes48>,
    proofs: Vec<c_kzg::Bytes48>,
    /* Only for constantine */
    secure_random_bytes: [u8; 32],
}

fuzz_target!(|input: Input| {
    let cnst = CONSTANTINE_CTX
        .get_or_init(|| initialize_constantine_ctx())
        .get();

    let blobs: Vec<[u8; c_kzg::BYTES_PER_BLOB]> =
        input.blobs.iter().map(|b| b.clone().into_inner()).collect();
    let commitments: Vec<[u8; c_kzg::BYTES_PER_COMMITMENT]> =
        input.commitments.iter().map(|c| c.into_inner()).collect();
    let proofs: Vec<[u8; c_kzg::BYTES_PER_PROOF]> =
        input.proofs.iter().map(|p| p.into_inner()).collect();

    let ckzg_result =
        KZG_SETTINGS.verify_blob_kzg_proof_batch(&input.blobs, &input.commitments, &input.proofs);
    let cnst_result = cnst.verify_blob_kzg_proof_batch(
        blobs.as_slice(),
        commitments.as_slice(),
        proofs.as_slice(),
        &input.secure_random_bytes,
    );

    match (&ckzg_result, &cnst_result) {
        (Ok(ckzg_valid), Ok(cnst_valid)) => {
            assert_eq!(*ckzg_valid, *cnst_valid);
        }
        (Err(_), Err(_)) => {
            // Cannot compare errors, they are unique.
        }
        _ => {
            // There is a disagreement.
            panic!("mismatch {:?} and {:?}", &ckzg_result, &cnst_result);
        }
    }
});
