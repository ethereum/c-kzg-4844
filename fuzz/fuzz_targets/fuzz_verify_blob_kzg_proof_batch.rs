// Run with the following command:
// cargo fuzz run fuzz_verify_blob_kzg_proof_batch

#![no_main]
extern crate core;

use arbitrary::Arbitrary;
use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;
use rust_eth_kzg::DASContext;
use std::cell::UnsafeCell;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

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
    static ref KZG_SETTINGS: c_kzg::KzgSettings = {
        let trusted_setup_file = get_root_dir().join("src").join("trusted_setup.txt");
        c_kzg::KzgSettings::load_trusted_setup_file(&trusted_setup_file, 0).unwrap()
    };
    static ref DAS_CONTEXT: DASContext = DASContext::default();
}

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
    let trusted_setup_file = get_root_dir().join("src").join("trusted_setup.txt");
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

    /* A version for constantine */
    let blobs: Vec<[u8; c_kzg::BYTES_PER_BLOB]> =
        input.blobs.iter().map(|b| b.clone().into_inner()).collect();
    let commitments: Vec<[u8; c_kzg::BYTES_PER_COMMITMENT]> =
        input.commitments.iter().map(|c| c.into_inner()).collect();
    let proofs: Vec<[u8; c_kzg::BYTES_PER_PROOF]> =
        input.proofs.iter().map(|p| p.into_inner()).collect();

    /* A second version for rust-eth-kzg */
    let blobs_vec: Vec<[u8; c_kzg::BYTES_PER_BLOB]> =
        input.blobs.iter().map(|b| b.clone().into_inner()).collect();
    let blobs_refs: Vec<&[u8; c_kzg::BYTES_PER_BLOB]> = blobs_vec.iter().collect();
    let commitments_vec: Vec<[u8; c_kzg::BYTES_PER_COMMITMENT]> =
        input.commitments.iter().map(|c| c.into_inner()).collect();
    let commitments_refs: Vec<&[u8; c_kzg::BYTES_PER_COMMITMENT]> =
        commitments_vec.iter().collect();
    let proofs_vec: Vec<[u8; c_kzg::BYTES_PER_PROOF]> =
        input.proofs.iter().map(|p| p.into_inner()).collect();
    let proofs_refs: Vec<&[u8; c_kzg::BYTES_PER_PROOF]> = proofs_vec.iter().collect();

    let ckzg_result =
        KZG_SETTINGS.verify_blob_kzg_proof_batch(&input.blobs, &input.commitments, &input.proofs);
    let cnst_result = cnst.verify_blob_kzg_proof_batch(
        blobs.as_slice(),
        commitments.as_slice(),
        proofs.as_slice(),
        &input.secure_random_bytes,
    );
    let rkzg_result =
        DAS_CONTEXT.verify_blob_kzg_proof_batch(blobs_refs, commitments_refs, proofs_refs);

    match (&ckzg_result, &cnst_result, &rkzg_result) {
        (Ok(ckzg_valid), Ok(cnst_valid), Ok(())) => {
            // One returns a boolean, the other just says Ok.
            assert_eq!(*ckzg_valid, true);
            assert_eq!(*cnst_valid, true);
        }
        (Ok(ckzg_valid), Ok(cnst_valid), Err(err)) => {
            // If ckzg was Ok, ensure the proof was rejected.
            assert_eq!(*ckzg_valid, false);
            assert_eq!(*cnst_valid, false);
            if !err.is_proof_invalid() {
                panic!("Expected InvalidProof, got {:?}", err);
            }
        }
        (Err(_), Err(_), Err(_)) => {
            // Cannot compare errors, they are unique.
        }
        _ => {
            // There is a disagreement.
            panic!(
                "mismatch: {:?}, {:?}, {:?}",
                &ckzg_result, &cnst_result, &rkzg_result
            );
        }
    }
});
