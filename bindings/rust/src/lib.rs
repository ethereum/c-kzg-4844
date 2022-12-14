#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

mod bindings;
use bindings::{g1_t, Blob, C_KZG_RET};
use libc::fopen;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::unix::prelude::OsStrExt;
use std::path::PathBuf;

pub use bindings::{
    BYTES_PER_BLOB, BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, BYTES_PER_PROOF,
    FIAT_SHAMIR_PROTOCOL_DOMAIN, FIELD_ELEMENTS_PER_BLOB,
};

const BYTES_PER_G1_POINT: usize = 48;

#[derive(Debug)]
// TODO(add separate error type for commitments and proof)
pub enum Error {
    /// The KZG proof is invalid.
    InvalidKZGProof(String),
    /// The KZG commitment is invalid.
    InvalidKZGCommitment(String),
    /// The underlying c-kzg library returned an error.
    CError(C_KZG_RET),
}

pub fn bytes_to_g1(bytes: &[u8]) -> Result<g1_t, Error> {
    let mut g1_point = MaybeUninit::<g1_t>::uninit();
    unsafe {
        let res = bindings::bytes_to_g1(g1_point.as_mut_ptr(), bytes.as_ptr());
        if let C_KZG_RET::C_KZG_OK = res {
            Ok(g1_point.assume_init())
        } else {
            Err(Error::CError(res))
        }
    }
}

pub fn bytes_from_g1(g1_point: g1_t) -> [u8; BYTES_PER_G1_POINT] {
    let mut bytes = [0; 48];
    unsafe { bindings::bytes_from_g1(bytes.as_mut_ptr(), &g1_point) }
    bytes
}

#[derive(Debug, Clone, Copy)]
pub struct BLSFieldElement(bindings::BLSFieldElement);

impl BLSFieldElement {
    pub fn bytes_to_bls_field(bytes: [u8; BYTES_PER_FIELD_ELEMENT as usize]) -> Self {
        let mut bls_field_element = MaybeUninit::<bindings::BLSFieldElement>::uninit();
        unsafe {
            bindings::bytes_to_bls_field(bls_field_element.as_mut_ptr(), bytes.as_ptr());
            Self(bls_field_element.assume_init())
        }
    }
}

pub struct KZGSettings(bindings::KZGSettings);
impl KZGSettings {
    pub fn load_trusted_setup(file_path: PathBuf) -> Result<Self, C_KZG_RET> {
        let file_path = CString::new(file_path.as_os_str().as_bytes()).unwrap();
        let mut kzg_settings = MaybeUninit::<bindings::KZGSettings>::uninit();
        unsafe {
            let file_ptr = fopen(file_path.as_ptr(), &('r' as libc::c_char));
            let res = bindings::load_trusted_setup(kzg_settings.as_mut_ptr(), file_ptr);
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(Self(kzg_settings.assume_init()))
            } else {
                Err(res)
            }
        }
    }
}

impl Drop for KZGSettings {
    fn drop(&mut self) {
        unsafe { bindings::free_trusted_setup(&mut self.0) }
    }
}

pub struct KZGProof(bindings::KZGProof);

impl KZGProof {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES_PER_PROOF {
            return Err(Error::InvalidKZGProof(format!(
                "Invalid byte length. Expected {} got {}",
                BYTES_PER_PROOF,
                bytes.len(),
            )));
        }
        let mut proof_bytes = [0; BYTES_PER_PROOF];
        proof_bytes.copy_from_slice(bytes);
        Ok(Self(bytes_to_g1(bytes)?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bytes_from_g1(self.0).to_vec()
    }

    pub fn as_hex_string(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn compute_aggregate_kzg_proof(
        blobs: &[Blob],
        kzg_settings: &KZGSettings,
    ) -> Result<Self, Error> {
        let mut kzg_proof = MaybeUninit::<bindings::KZGProof>::uninit();
        unsafe {
            let res = bindings::compute_aggregate_kzg_proof(
                kzg_proof.as_mut_ptr(),
                blobs.as_ptr(),
                blobs.len(),
                &kzg_settings.0,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(Self(kzg_proof.assume_init()))
            } else {
                Err(Error::CError(res))
            }
        }
    }

    pub fn verify_aggregate_kzg_proof(
        &self,
        blobs: &[Blob],
        expected_kzg_commitments: &[KZGCommitment],
        kzg_settings: &KZGSettings,
    ) -> Result<bool, Error> {
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = bindings::verify_aggregate_kzg_proof(
                verified.as_mut_ptr(),
                blobs.as_ptr(),
                expected_kzg_commitments
                    .iter()
                    .map(|c| c.0)
                    .collect::<Vec<_>>()
                    .as_ptr(),
                blobs.len(),
                &self.0,
                &kzg_settings.0,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(verified.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }

    pub fn verify_kzg_proof(
        &self,
        kzg_commitment: KZGCommitment,
        z: BLSFieldElement,
        y: BLSFieldElement,
        kzg_settings: &KZGSettings,
    ) -> Result<bool, Error> {
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = bindings::verify_kzg_proof(
                verified.as_mut_ptr(),
                &kzg_commitment.0,
                &z.0,
                &y.0,
                &self.0,
                &kzg_settings.0,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(verified.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }
}

pub struct KZGCommitment(bindings::KZGCommitment);

impl KZGCommitment {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES_PER_COMMITMENT {
            return Err(Error::InvalidKZGCommitment(format!(
                "Invalid byte length. Expected {} got {}",
                BYTES_PER_PROOF,
                bytes.len(),
            )));
        }
        let mut proof_bytes = [0; BYTES_PER_COMMITMENT];
        proof_bytes.copy_from_slice(bytes);
        Ok(Self(bytes_to_g1(bytes)?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bytes_from_g1(self.0).to_vec()
    }

    pub fn as_hex_string(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn blob_to_kzg_commitment(mut blob: Blob, kzg_settings: &KZGSettings) -> Self {
        let mut kzg_commitment: MaybeUninit<bindings::KZGCommitment> = MaybeUninit::uninit();
        unsafe {
            bindings::blob_to_kzg_commitment(
                kzg_commitment.as_mut_ptr(),
                blob.as_mut_ptr(),
                &kzg_settings.0,
            );
            Self(kzg_commitment.assume_init())
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
