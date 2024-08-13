// Run with the following command:
// cargo fuzz run fuzz_blob_to_kzg_commitment

#![no_main]
extern crate core;

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

fuzz_target!(|blob: c_kzg::Blob| {
    let cnst = CONSTANTINE_CTX
        .get_or_init(|| initialize_constantine_ctx())
        .get();

    let ckzg_result = KZG_SETTINGS.blob_to_kzg_commitment(&blob);
    let cnst_result = cnst.blob_to_kzg_commitment(&blob);

    match (&ckzg_result, &cnst_result) {
        (Ok(ckzg_commitment), Ok(cnst_commitment)) => {
            // Ensure the results are the same.
            assert_eq!(*ckzg_commitment.as_slice(), *cnst_commitment.as_slice());
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
