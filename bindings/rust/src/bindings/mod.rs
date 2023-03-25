#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

mod test_formats;

include!("generated.rs");

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

/// A trusted (valid) KZG commitment.
// NOTE: this is a type alias to the struct Bytes48, same as [`KZGProof`] in the C header files. To
//       facilitate type safety: proofs and commitments should not be interchangeable, we use a
//       custom implementation.
#[repr(C)]
pub struct KZGCommitment {
    bytes: [u8; BYTES_PER_COMMITMENT],
}

/// A trusted (valid) KZG proof.
// NOTE: this is a type alias to the struct Bytes48, same as [`KZGCommitment`] in the C header
//       files. To facilitate type safety: proofs and commitments should not be interchangeable, we
//       use a custom implementation.
#[repr(C)]
pub struct KZGProof {
    bytes: [u8; BYTES_PER_PROOF],
}

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

impl Blob {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES_PER_BLOB {
            return Err(Error::InvalidBytesLength(format!(
                "Invalid byte length. Expected {} got {}",
                BYTES_PER_BLOB,
                bytes.len(),
            )));
        }
        let mut new_bytes = [0; BYTES_PER_BLOB];
        new_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: new_bytes })
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        Self::from_bytes(&hex::decode(&hex_str[2..]).unwrap())
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

    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        Self::from_bytes(&hex::decode(&hex_str[2..]).unwrap())
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

    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        Self::from_bytes(&hex::decode(&hex_str[2..]).unwrap())
    }

    pub fn into_inner(self) -> [u8; 48] {
        self.bytes
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
        Bytes48 { bytes: self.bytes }
    }

    pub fn as_hex_string(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn compute_kzg_proof(
        blob: Blob,
        z_bytes: Bytes32,
        kzg_settings: &KZGSettings,
    ) -> Result<(Self, Bytes32), Error> {
        let mut kzg_proof = MaybeUninit::<KZGProof>::uninit();
        let mut y_out = MaybeUninit::<Bytes32>::uninit();
        unsafe {
            let res = compute_kzg_proof(
                kzg_proof.as_mut_ptr(),
                y_out.as_mut_ptr(),
                &blob,
                &z_bytes,
                kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok((kzg_proof.assume_init(), y_out.assume_init()))
            } else {
                Err(Error::CError(res))
            }
        }
    }

    pub fn compute_blob_kzg_proof(
        blob: Blob,
        commitment_bytes: Bytes48,
        kzg_settings: &KZGSettings,
    ) -> Result<Self, Error> {
        let mut kzg_proof = MaybeUninit::<KZGProof>::uninit();
        unsafe {
            let res = compute_blob_kzg_proof(
                kzg_proof.as_mut_ptr(),
                &blob,
                &commitment_bytes,
                kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(kzg_proof.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }

    pub fn verify_kzg_proof(
        commitment_bytes: Bytes48,
        z_bytes: Bytes32,
        y_bytes: Bytes32,
        proof_bytes: Bytes48,
        kzg_settings: &KZGSettings,
    ) -> Result<bool, Error> {
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = verify_kzg_proof(
                verified.as_mut_ptr(),
                &commitment_bytes,
                &z_bytes,
                &y_bytes,
                &proof_bytes,
                kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(verified.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }

    pub fn verify_blob_kzg_proof(
        blob: Blob,
        commitment_bytes: Bytes48,
        proof_bytes: Bytes48,
        kzg_settings: &KZGSettings,
    ) -> Result<bool, Error> {
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = verify_blob_kzg_proof(
                verified.as_mut_ptr(),
                &blob,
                &commitment_bytes,
                &proof_bytes,
                kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(verified.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }

    pub fn verify_blob_kzg_proof_batch(
        blobs: &[Blob],
        commitments_bytes: &[Bytes48],
        proofs_bytes: &[Bytes48],
        kzg_settings: &KZGSettings,
    ) -> Result<bool, Error> {
        if blobs.len() != commitments_bytes.len() {
            return Err(Error::MismatchLength(format!(
                "There are {} blobs and {} commitments",
                blobs.len(),
                commitments_bytes.len()
            )));
        }
        if blobs.len() != proofs_bytes.len() {
            return Err(Error::MismatchLength(format!(
                "There are {} blobs and {} proofs",
                blobs.len(),
                proofs_bytes.len()
            )));
        }
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = verify_blob_kzg_proof_batch(
                verified.as_mut_ptr(),
                blobs.as_ptr(),
                commitments_bytes.as_ptr(),
                proofs_bytes.as_ptr(),
                blobs.len(),
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
        Bytes48 { bytes: self.bytes }
    }

    pub fn as_hex_string(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn blob_to_kzg_commitment(blob: Blob, kzg_settings: &KZGSettings) -> Result<Self, Error> {
        let mut kzg_commitment: MaybeUninit<KZGCommitment> = MaybeUninit::uninit();
        unsafe {
            let res = blob_to_kzg_commitment(
                kzg_commitment.as_mut_ptr(),
                blob.as_ptr() as *const Blob,
                kzg_settings,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(kzg_commitment.assume_init())
            } else {
                Err(Error::CError(res))
            }
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

use std::ops::{Deref, DerefMut};

impl Deref for Bytes32 {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Deref for Bytes48 {
    type Target = [u8; 48];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Deref for Blob {
    type Target = [u8; BYTES_PER_BLOB];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for Blob {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        Blob { bytes: self.bytes }
    }
}

impl Deref for KZGProof {
    type Target = [u8; BYTES_PER_PROOF];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Deref for KZGCommitment {
    type Target = [u8; BYTES_PER_COMMITMENT];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// Safety: FFTSettings is initialized once on calling `load_trusted_setup`. After
/// that, the struct is never modified. The memory for the arrays within `FFTSettings` and
/// `g1_values` and `g2_values` are only freed on calling `free_trusted_setup` which only happens
/// when we drop the struct.
unsafe impl Sync for KZGSettings {}
unsafe impl Send for KZGSettings {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::ThreadRng, Rng};
    use std::fs;

    use test_formats::{
        blob_to_kzg_commitment_test, compute_blob_kzg_proof, compute_kzg_proof,
        verify_blob_kzg_proof, verify_blob_kzg_proof_batch, verify_kzg_proof,
    };

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
            .iter()
            .map(|blob| KZGCommitment::blob_to_kzg_commitment(blob.clone(), &kzg_settings).unwrap())
            .map(|commitment| commitment.to_bytes())
            .collect();

        let proofs: Vec<Bytes48> = blobs
            .iter()
            .zip(commitments.iter())
            .map(|(blob, commitment)| {
                KZGProof::compute_blob_kzg_proof(blob.clone(), *commitment, &kzg_settings).unwrap()
            })
            .map(|proof| proof.to_bytes())
            .collect();

        assert!(KZGProof::verify_blob_kzg_proof_batch(
            &blobs,
            &commitments,
            &proofs,
            &kzg_settings
        )
        .unwrap());

        blobs.pop();

        let error =
            KZGProof::verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs, &kzg_settings)
                .unwrap_err();
        assert!(matches!(error, Error::MismatchLength(_)));

        let incorrect_blob = generate_random_blob(&mut rng);
        blobs.push(incorrect_blob);

        assert!(!KZGProof::verify_blob_kzg_proof_batch(
            &blobs,
            &commitments,
            &proofs,
            &kzg_settings
        )
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

    const BLOB_TO_KZG_COMMITMENT_TESTS: &str = "../../tests/blob_to_kzg_commitment/*/*/*";
    const COMPUTE_KZG_PROOF_TESTS: &str = "../../tests/compute_kzg_proof/*/*/*";
    const COMPUTE_BLOB_KZG_PROOF_TESTS: &str = "../../tests/compute_blob_kzg_proof/*/*/*";
    const VERIFY_KZG_PROOF_TESTS: &str = "../../tests/verify_kzg_proof/*/*/*";
    const VERIFY_BLOB_KZG_PROOF_TESTS: &str = "../../tests/verify_blob_kzg_proof/*/*/*";
    const VERIFY_BLOB_KZG_PROOF_BATCH_TESTS: &str = "../../tests/verify_blob_kzg_proof_batch/*/*/*";

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_blob_to_kzg_commitment() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(BLOB_TO_KZG_COMMITMENT_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: blob_to_kzg_commitment_test::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let Ok(blob) = test.input.get_blob() else {
                assert!(test.get_output().is_none());
                continue;
            };

            match KZGCommitment::blob_to_kzg_commitment(blob, &kzg_settings) {
                Ok(res) => assert_eq!(res.bytes, test.get_output().unwrap().bytes),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_compute_kzg_proof() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(COMPUTE_KZG_PROOF_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: compute_kzg_proof::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(blob), Ok(z)) = (test.input.get_blob(), test.input.get_z()) else {
                assert!(test.get_output().is_none());
                continue;
            };

            match KZGProof::compute_kzg_proof(blob, z, &kzg_settings) {
                Ok((proof, y)) => {
                    assert_eq!(proof.bytes, test.get_output().unwrap().0.bytes);
                    assert_eq!(y.bytes, test.get_output().unwrap().1.bytes);
                }
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_compute_blob_kzg_proof() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(COMPUTE_BLOB_KZG_PROOF_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: compute_blob_kzg_proof::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(blob), Ok(commitment)) = (
                test.input.get_blob(),
                test.input.get_commitment()
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            match KZGProof::compute_blob_kzg_proof(blob, commitment, &kzg_settings) {
                Ok(res) => assert_eq!(res.bytes, test.get_output().unwrap().bytes),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_verify_kzg_proof() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(VERIFY_KZG_PROOF_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: verify_kzg_proof::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(commitment), Ok(z), Ok(y), Ok(proof)) = (
                test.input.get_commitment(),
                test.input.get_z(),
                test.input.get_y(),
                test.input.get_proof()
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            match KZGProof::verify_kzg_proof(commitment, z, y, proof, &kzg_settings) {
                Ok(res) => assert_eq!(res, test.get_output().unwrap()),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_verify_blob_kzg_proof() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(VERIFY_BLOB_KZG_PROOF_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: verify_blob_kzg_proof::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(blob), Ok(commitment), Ok(proof)) = (
                test.input.get_blob(),
                test.input.get_commitment(),
                test.input.get_proof()
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            match KZGProof::verify_blob_kzg_proof(blob, commitment, proof, &kzg_settings) {
                Ok(res) => assert_eq!(res, test.get_output().unwrap()),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_verify_blob_kzg_proof_batch() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
        let test_files: Vec<PathBuf> = glob::glob(VERIFY_BLOB_KZG_PROOF_BATCH_TESTS)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!test_files.is_empty());

        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: verify_blob_kzg_proof_batch::Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(blobs), Ok(commitments), Ok(proofs)) = (
                test.input.get_blobs(),
                test.input.get_commitments(),
                test.input.get_proofs()
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            match KZGProof::verify_blob_kzg_proof_batch(
                &blobs,
                &commitments,
                &proofs,
                &kzg_settings,
            ) {
                Ok(res) => assert_eq!(res, test.get_output().unwrap()),
                _ => assert!(test.get_output().is_none()),
            }
        }
    }
}
