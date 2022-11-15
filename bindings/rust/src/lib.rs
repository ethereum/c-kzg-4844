#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("../bindings.rs");

use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::unix::prelude::OsStrExt;
use std::path::PathBuf;

impl g1_t {
    pub fn bytes_to_g1(bytes: &[u8]) -> Result<Self, C_KZG_RET> {
        let mut g1_point = MaybeUninit::<g1_t>::uninit();
        unsafe {
            let res = bytes_to_g1(g1_point.as_mut_ptr(), bytes.as_ptr());
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(g1_point.assume_init())
            } else {
                Err(res)
            }
        }
    }

    pub fn bytes_from_g1(&self) -> [u8; 48] {
        let mut bytes = [0; 48];
        unsafe { bytes_from_g1(bytes.as_mut_ptr(), self) }
        bytes
    }
}

impl BLSFieldElement {
    pub fn bytes_to_bls_field(bytes: [u8; BYTES_PER_FIELD_ELEMENT as usize]) -> Self {
        let mut bls_field_element = MaybeUninit::<BLSFieldElement>::uninit();
        unsafe {
            bytes_to_bls_field(bls_field_element.as_mut_ptr(), bytes.as_ptr());
            bls_field_element.assume_init()
        }
    }
}

impl KZGSettings {
    pub fn load_trusted_setup(file_path: PathBuf) -> Result<Self, C_KZG_RET> {
        let file_path = CString::new(file_path.as_os_str().as_bytes()).unwrap();
        let mut kzg_settings = MaybeUninit::<KZGSettings>::uninit();
        unsafe {
            let file_ptr = fopen(file_path.as_ptr(), &('r' as libc::c_char));
            let res = load_trusted_setup(kzg_settings.as_mut_ptr(), file_ptr);
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(kzg_settings.assume_init())
            } else {
                Err(res)
            }
        }
    }
}

impl Drop for KZGSettings {
    fn drop(&mut self) {
        unsafe { free_trusted_setup(self) }
    }
}

impl KZGProof {
    pub fn compute_aggregate_kzg_proof(
        blobs: &[Blob],
        kzg_settings: &KZGSettings,
    ) -> Result<Self, C_KZG_RET> {
        let mut kzg_proof = MaybeUninit::<KZGProof>::uninit();
        unsafe {
            let res = compute_aggregate_kzg_proof(
                kzg_proof.as_mut_ptr(),
                blobs.as_ptr(),
                blobs.len(),
                kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(kzg_proof.assume_init())
            } else {
                Err(res)
            }
        }
    }

    pub fn verify_aggregate_kzg_proof(
        &self,
        blobs: &[Blob],
        expected_kzg_commitments: &[KZGCommitment],
        kzg_settings: &KZGSettings,
    ) -> Result<bool, C_KZG_RET> {
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = verify_aggregate_kzg_proof(
                verified.as_mut_ptr(),
                blobs.as_ptr(),
                expected_kzg_commitments.as_ptr(),
                blobs.len(),
                self,
                kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(verified.assume_init())
            } else {
                Err(res)
            }
        }
    }

    pub fn verify_kzg_proof(
        &self,
        kzg_commitment: KZGCommitment,
        z: BLSFieldElement,
        y: BLSFieldElement,
        kzg_settings: &KZGSettings,
    ) -> Result<bool, C_KZG_RET> {
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = verify_kzg_proof(
                verified.as_mut_ptr(),
                &kzg_commitment,
                &z,
                &y,
                self,
                kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(verified.assume_init())
            } else {
                Err(res)
            }
        }
    }
}

impl KZGCommitment {
    pub fn blob_to_kzg_commitment(mut blob: Blob, kzg_settings: &KZGSettings) -> Self {
        let mut kzg_commitment: MaybeUninit<KZGCommitment> = MaybeUninit::uninit();
        unsafe {
            blob_to_kzg_commitment(kzg_commitment.as_mut_ptr(), blob.as_mut_ptr(), kzg_settings);
            kzg_commitment.assume_init()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load() {
        {
            let a = KZGSettings::load_trusted_setup(PathBuf::from(
                "/home/pawan/eth2/c-kzg/src/trusted_setup.txt",
            ));
            assert!(a.is_ok());
        }
    }
}
