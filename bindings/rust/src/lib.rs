#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("bindings.rs");

use libc::fopen;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::unix::prelude::OsStrExt;
use std::path::PathBuf;

pub const BYTES_PER_G1_POINT: usize = 48;
pub const BYTES_PER_G2_POINT: usize = 96;

/// Number of G2 points required for the kzg trusted setup.
/// 65 is fixed and is used for providing multiproofs up to 64 field elements.
const NUM_G2_POINTS: usize = 65;

#[derive(Debug)]
pub enum Error {
    /// Wrong number of bytes.
    InvalidBytesLength(String),
    /// The KZG proof is invalid.
    InvalidKzgProof(String),
    /// The KZG commitment is invalid.
    InvalidKzgCommitment(String),
    /// The provided trusted setup is invalid.
    InvalidTrustedSetup(String),
    /// Paired arguments have different lengths.
    MismatchLength(String),
    /// The underlying c-kzg library returned an error.
    CError(C_KZG_RET),
}

/// Holds the parameters of a kzg trusted setup ceremony.
impl KZGSettings {
    /// Initializes a trusted setup from `FIELD_ELEMENTS_PER_BLOB` g1 points
    /// and 65 g2 points in byte format.
    pub fn load_trusted_setup(
        g1_bytes: Vec<[u8; BYTES_PER_G1_POINT]>,
        g2_bytes: Vec<[u8; BYTES_PER_G2_POINT]>,
    ) -> Result<Self, Error> {
        if g1_bytes.len() != FIELD_ELEMENTS_PER_BLOB {
            return Err(Error::InvalidTrustedSetup(format!(
                "Invalid number of g1 points in trusted setup. Expected {} got {}",
                FIELD_ELEMENTS_PER_BLOB,
                g1_bytes.len()
            )));
        }
        if g2_bytes.len() != NUM_G2_POINTS {
            return Err(Error::InvalidTrustedSetup(format!(
                "Invalid number of g2 points in trusted setup. Expected {} got {}",
                NUM_G2_POINTS,
                g2_bytes.len()
            )));
        }
        let mut kzg_settings = MaybeUninit::<KZGSettings>::uninit();
        unsafe {
            let res = load_trusted_setup(
                kzg_settings.as_mut_ptr(),
                g1_bytes.as_ptr() as *const u8,
                g1_bytes.len(),
                g2_bytes.as_ptr() as *const u8,
                g2_bytes.len(),
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(kzg_settings.assume_init())
            } else {
                Err(Error::InvalidTrustedSetup(format!(
                    "Invalid trusted setup: {:?}",
                    res
                )))
            }
        }
    }

    /// Loads the trusted setup parameters from a file. The file format is as follows:
    ///
    /// FIELD_ELEMENTS_PER_BLOB
    /// 65 # This is fixed and is used for providing multiproofs up to 64 field elements.
    /// FIELD_ELEMENT_PER_BLOB g1 byte values
    /// 65 g2 byte values
    pub fn load_trusted_setup_file(file_path: PathBuf) -> Result<Self, Error> {
        let file_path = CString::new(file_path.as_os_str().as_bytes()).map_err(|e| {
            Error::InvalidTrustedSetup(format!("Invalid trusted setup file: {:?}", e))
        })?;
        let mut kzg_settings = MaybeUninit::<KZGSettings>::uninit();
        unsafe {
            let file_ptr = fopen(file_path.as_ptr(), &('r' as libc::c_char));
            let res = load_trusted_setup_file(kzg_settings.as_mut_ptr(), file_ptr);
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(kzg_settings.assume_init())
            } else {
                Err(Error::InvalidTrustedSetup(format!(
                    "Invalid trusted setup: {:?}",
                    res
                )))
            }
        }
    }
}

impl Drop for KZGSettings {
    fn drop(&mut self) {
        unsafe { free_trusted_setup(self) }
    }
}

impl Bytes32 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 32 {
            return Err(Error::InvalidBytesLength(format!(
                "Invalid byte length. Expected {} got {}",
                32,
                bytes.len(),
            )));
        }
        let mut new_bytes = [0; 32];
        new_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: new_bytes })
    }
}

impl Bytes48 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 48 {
            return Err(Error::InvalidBytesLength(format!(
                "Invalid byte length. Expected {} got {}",
                48,
                bytes.len(),
            )));
        }
        let mut new_bytes = [0; 48];
        new_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: new_bytes })
    }
}

impl KZGProof {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES_PER_PROOF {
            return Err(Error::InvalidKzgProof(format!(
                "Invalid byte length. Expected {} got {}",
                BYTES_PER_PROOF,
                bytes.len(),
            )));
        }
        let mut proof_bytes = [0; BYTES_PER_PROOF];
        proof_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: proof_bytes })
    }

    pub fn to_bytes(&self) -> Bytes48 {
        let mut bytes = [0; 48];
        bytes.copy_from_slice(&self.bytes);
        Bytes48 { bytes }
    }

    pub fn as_hex_string(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn compute_kzg_proof(
        blob: &[Blob],
        z_bytes: Bytes32,
        kzg_settings: &KZGSettings,
    ) -> Result<Self, Error> {
        let mut kzg_proof = MaybeUninit::<KZGProof>::uninit();
        unsafe {
            let res = compute_kzg_proof(
                kzg_proof.as_mut_ptr(),
                blob.as_ptr(),
                &z_bytes,
                kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(kzg_proof.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }

    pub fn compute_aggregate_kzg_proof(
        blobs: &[Blob],
        kzg_settings: &KZGSettings,
    ) -> Result<Self, Error> {
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
                Err(Error::CError(res))
            }
        }
    }

    pub fn verify_aggregate_kzg_proof(
        &self,
        blobs: &[Blob],
        commitments_bytes: &[Bytes48],
        kzg_settings: &KZGSettings,
    ) -> Result<bool, Error> {
        if blobs.len() != commitments_bytes.len() {
            return Err(Error::MismatchLength(format!(
                "There are {} blobs and {} commitments",
                blobs.len(),
                commitments_bytes.len()
            )));
        }
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = verify_aggregate_kzg_proof(
                verified.as_mut_ptr(),
                blobs.as_ptr(),
                commitments_bytes.as_ptr(),
                blobs.len(),
                &self.to_bytes(),
                kzg_settings,
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
        commitment_bytes: Bytes48,
        z_bytes: Bytes32,
        y_bytes: Bytes32,
        kzg_settings: &KZGSettings,
    ) -> Result<bool, Error> {
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = verify_kzg_proof(
                verified.as_mut_ptr(),
                &commitment_bytes,
                &z_bytes,
                &y_bytes,
                &self.to_bytes(),
                kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(verified.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }
}

impl KZGCommitment {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES_PER_COMMITMENT {
            return Err(Error::InvalidKzgCommitment(format!(
                "Invalid byte length. Expected {} got {}",
                BYTES_PER_PROOF,
                bytes.len(),
            )));
        }
        let mut commitment = [0; BYTES_PER_COMMITMENT];
        commitment.copy_from_slice(bytes);
        Ok(Self { bytes: commitment })
    }

    pub fn to_bytes(&self) -> Bytes48 {
        let mut bytes = [0; 48];
        bytes.copy_from_slice(&self.bytes);
        Bytes48 { bytes }
    }

    pub fn as_hex_string(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn blob_to_kzg_commitment(blob: Blob, kzg_settings: &KZGSettings) -> Self {
        let mut kzg_commitment: MaybeUninit<KZGCommitment> = MaybeUninit::uninit();
        unsafe {
            blob_to_kzg_commitment(
                kzg_commitment.as_mut_ptr(),
                blob.as_ptr() as *const Blob,
                kzg_settings,
            );
            kzg_commitment.assume_init()
        }
    }
}

impl From<[u8; BYTES_PER_COMMITMENT]> for KZGCommitment {
    fn from(value: [u8; BYTES_PER_COMMITMENT]) -> Self {
        Self { bytes: value }
    }
}

impl From<[u8; BYTES_PER_PROOF]> for KZGProof {
    fn from(value: [u8; BYTES_PER_PROOF]) -> Self {
        Self { bytes: value }
    }
}

impl From<[u8; BYTES_PER_BLOB]> for Blob {
    fn from(value: [u8; BYTES_PER_BLOB]) -> Self {
        Self { bytes: value }
    }
}

impl From<[u8; 32]> for Bytes32 {
    fn from(value: [u8; 32]) -> Self {
        Self { bytes: value }
    }
}

impl From<[u8; 48]> for Bytes48 {
    fn from(value: [u8; 48]) -> Self {
        Self { bytes: value }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::ThreadRng, Rng};

    fn generate_random_blob(rng: &mut ThreadRng) -> Blob {
        let mut arr = [0u8; BYTES_PER_BLOB];
        rng.fill(&mut arr[..]);
        // Ensure that the blob is canonical by ensuring that
        // each field element contained in the blob is < BLS_MODULUS
        for i in 0..FIELD_ELEMENTS_PER_BLOB {
            arr[i * BYTES_PER_FIELD_ELEMENT + BYTES_PER_FIELD_ELEMENT - 1] = 0;
        }
        arr.into()
    }

    fn test_simple(trusted_setup_file: PathBuf) {
        let mut rng = rand::thread_rng();
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let num_blobs: usize = rng.gen_range(1..16);
        let mut blobs: Vec<Blob> = (0..num_blobs)
            .map(|_| generate_random_blob(&mut rng))
            .collect();

        let commitments: Vec<Bytes48> = blobs
            .clone()
            .into_iter()
            .map(|blob| KZGCommitment::blob_to_kzg_commitment(blob, &kzg_settings))
            .map(|commitment| commitment.to_bytes())
            .collect();

        let kzg_proof = KZGProof::compute_aggregate_kzg_proof(&blobs, &kzg_settings).unwrap();

        assert!(kzg_proof
            .verify_aggregate_kzg_proof(&blobs, &commitments, &kzg_settings)
            .unwrap());

        blobs.pop();

        let error = kzg_proof
            .verify_aggregate_kzg_proof(&blobs, &commitments, &kzg_settings)
            .unwrap_err();
        assert!(matches!(error, Error::MismatchLength(_)));

        let incorrect_blob = generate_random_blob(&mut rng);
        blobs.push(incorrect_blob);

        assert!(!kzg_proof
            .verify_aggregate_kzg_proof(&blobs, &commitments, &kzg_settings)
            .unwrap());
    }

    #[test]
    fn test_end_to_end() {
        let trusted_setup_file = if cfg!(feature = "minimal-spec") {
            PathBuf::from("../../src/trusted_setup_4.txt")
        } else {
            PathBuf::from("../../src/trusted_setup.txt")
        };
        test_simple(trusted_setup_file);
    }

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_compute_agg_proof() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let test_file = PathBuf::from("test_vectors/public_agg_proof.json");
        let json_data: serde_json::Value =
            serde_json::from_reader(std::fs::File::open(test_file).unwrap()).unwrap();

        let tests = json_data.get("TestCases").unwrap().as_array().unwrap();
        for test in tests.iter() {
            let expected_proof = test.get("Proof").unwrap().as_str().unwrap();

            let expected_commitments = test
                .get("Commitments")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|data| data.as_str().unwrap())
                .collect::<Vec<_>>();

            let blobs = test
                .get("Polynomials")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|data| {
                    let data = data.as_str().unwrap();
                    let blob = hex::decode(data).unwrap();
                    let mut blob_data = [0; BYTES_PER_BLOB];
                    blob_data.copy_from_slice(&blob);
                    Blob { bytes: blob_data }
                })
                .collect::<Vec<_>>();

            let proof = KZGProof::compute_aggregate_kzg_proof(&blobs, &kzg_settings).unwrap();
            assert_eq!(proof.as_hex_string(), expected_proof);

            for (i, blob) in blobs.into_iter().enumerate() {
                let commitment = KZGCommitment::blob_to_kzg_commitment(blob, &kzg_settings);
                assert_eq!(
                    commitment.as_hex_string().as_str(),
                    expected_commitments[i]
                );
            }
        }
    }

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_verify_kzg_proof() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let test_file = PathBuf::from("test_vectors/public_verify_kzg_proof.json");
        let json_data: serde_json::Value =
            serde_json::from_reader(std::fs::File::open(test_file).unwrap()).unwrap();

        let tests = json_data.get("TestCases").unwrap().as_array().unwrap();
        for test in tests.iter() {
            let proof = test.get("Proof").unwrap().as_str().unwrap();
            let kzg_proof = KZGProof::from_bytes(&hex::decode(proof).unwrap()).unwrap();

            let commitment_hex = test.get("Commitment").unwrap().as_str().unwrap();
            let commitment = Bytes48::from_bytes(&hex::decode(commitment_hex).unwrap()).unwrap();

            let z_hex = test.get("InputPoint").unwrap().as_str().unwrap();
            let z_bytes = Bytes32::from_bytes(&hex::decode(z_hex).unwrap()).unwrap();

            let y_hex = test.get("ClaimedValue").unwrap().as_str().unwrap();
            let y_bytes = Bytes32::from_bytes(&hex::decode(y_hex).unwrap()).unwrap();

            assert!(kzg_proof
                .verify_kzg_proof(
                    commitment,
                    z_bytes,
                    y_bytes,
                    &kzg_settings
                )
                .unwrap());
        }
    }
}
