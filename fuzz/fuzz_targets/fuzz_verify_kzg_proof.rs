// Run with the following command:
// cargo fuzz run fuzz_verify_kzg_proof

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
    commitment: c_kzg::Bytes48,
    z: c_kzg::Bytes32,
    y: c_kzg::Bytes32,
    proof: c_kzg::Bytes48,
}

fuzz_target!(|input: Input| {
    let cnst = CONSTANTINE_CTX
        .get_or_init(|| initialize_constantine_ctx())
        .get();

    let ckzg_result =
        KZG_SETTINGS.verify_kzg_proof(&input.commitment, &input.z, &input.y, &input.proof);
    let cnst_result = cnst.verify_kzg_proof(&input.commitment, &input.z, &input.y, &input.proof);
    let rkzg_result =
        DAS_CONTEXT.verify_kzg_proof(&input.commitment, *input.z, *input.y, &input.proof);

    match (&ckzg_result, &cnst_result, &rkzg_result) {
        (Ok(ckzg_valid), Ok(cnst_valid), Ok(())) => {
            assert_eq!(*ckzg_valid, *cnst_valid);
            assert_eq!(*ckzg_valid, true);
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
