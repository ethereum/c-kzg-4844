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
        blob: Blob,
        z_bytes: Bytes32,
        kzg_settings: &KZGSettings,
    ) -> Result<Self, Error> {
        let mut kzg_proof = MaybeUninit::<KZGProof>::uninit();
        unsafe {
            let res = compute_kzg_proof(kzg_proof.as_mut_ptr(), &blob, &z_bytes, kzg_settings);
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(kzg_proof.assume_init())
            } else {
                Err(Error::CError(res))
            }
        }
    }

    pub fn compute_blob_kzg_proof(blob: Blob, kzg_settings: &KZGSettings) -> Result<Self, Error> {
        let mut kzg_proof = MaybeUninit::<KZGProof>::uninit();
        unsafe {
            let res = compute_blob_kzg_proof(kzg_proof.as_mut_ptr(), &blob, kzg_settings);
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
    ) -> Result<(), Error> {
        let res: C_KZG_RET  =
            unsafe {
                verify_kzg_proof(
                    &commitment_bytes,
                    &z_bytes,
                    &y_bytes,
                    &proof_bytes,
                    kzg_settings,
                )
        };
        if res == C_KZG_RET::C_KZG_OK {
            Ok(())
        } else {
            Err(Error::CError(res))
        }
    }

    pub fn verify_blob_kzg_proof(
        blob: Blob,
        commitment_bytes: Bytes48,
        proof_bytes: Bytes48,
        kzg_settings: &KZGSettings,
    ) -> Result<(), Error> {
        let res: C_KZG_RET  =
            unsafe {
                verify_blob_kzg_proof(
                    &blob,
                    &commitment_bytes,
                    &proof_bytes,
                    kzg_settings,
                )
            };
        if res == C_KZG_RET::C_KZG_OK {
            Ok(())
        } else {
            Err(Error::CError(res))
        }
    }

    pub fn verify_blob_kzg_proof_batch(
        blobs: &[Blob],
        commitments_bytes: &[Bytes48],
        proofs_bytes: &[Bytes48],
        kzg_settings: &KZGSettings,
    ) -> Result<(), Error> {
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
        let res: C_KZG_RET =
            unsafe {
                verify_blob_kzg_proof_batch(
                    blobs.as_ptr(),
                    commitments_bytes.as_ptr(),
                    proofs_bytes.as_ptr(),
                    blobs.len(),
                    kzg_settings,
                )
            };
        if res == C_KZG_RET::C_KZG_OK {
            Ok(())
        } else {
            Err(Error::CError(res))
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::ThreadRng, Rng};
    use std::fs;

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
            .map(|blob| KZGCommitment::blob_to_kzg_commitment(blob, &kzg_settings).unwrap())
            .map(|commitment| commitment.to_bytes())
            .collect();

        let proofs: Vec<Bytes48> = blobs
            .clone()
            .into_iter()
            .map(|blob| KZGProof::compute_blob_kzg_proof(blob, &kzg_settings).unwrap())
            .map(|proof| proof.to_bytes())
            .collect();

        assert!(KZGProof::verify_blob_kzg_proof_batch(
            &blobs,
            &commitments,
            &proofs,
            &kzg_settings
        )
        .is_ok());

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
        .is_ok());
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

    fn get_blob(path: PathBuf) -> Blob {
        let input_str = fs::read_to_string(path).unwrap();
        let input_bytes = hex::decode(input_str.as_bytes()).unwrap();
        Blob::from_bytes(input_bytes.as_slice()).unwrap()
    }

    fn get_bytes32(path: PathBuf) -> Bytes32 {
        let input_str = fs::read_to_string(path).unwrap();
        let input_bytes = hex::decode(input_str.as_bytes()).unwrap();
        Bytes32::from_bytes(input_bytes.as_slice()).unwrap()
    }

    fn get_bytes48(path: PathBuf) -> Bytes48 {
        let input_str = fs::read_to_string(path).unwrap();
        let input_bytes = hex::decode(input_str.as_bytes()).unwrap();
        Bytes48::from_bytes(input_bytes.as_slice()).unwrap()
    }

    fn get_boolean(path: PathBuf) -> bool {
        let input_str = fs::read_to_string(path).unwrap();
        input_str.contains("true")
    }

    const BLOB_TO_KZG_COMMITMENT_TESTS: &str = "../../tests/blob_to_kzg_commitment/";
    const COMPUTE_KZG_PROOF_TESTS: &str = "../../tests/compute_kzg_proof/";
    const COMPUTE_BLOB_KZG_PROOF_TESTS: &str = "../../tests/compute_blob_kzg_proof/";
    const VERIFY_KZG_PROOF_TESTS: &str = "../../tests/verify_kzg_proof/";
    const VERIFY_BLOB_KZG_PROOF_TESTS: &str = "../../tests/verify_blob_kzg_proof/";
    const VERIFY_BLOB_KZG_PROOF_BATCH_TESTS: &str = "../../tests/verify_blob_kzg_proof_batch/";

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_blob_to_kzg_commitment() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let tests = fs::read_dir(BLOB_TO_KZG_COMMITMENT_TESTS)
            .unwrap()
            .map(|t| t.unwrap().path());
        for test in tests {
            let blob = get_blob(test.join("blob.txt"));
            let res = KZGCommitment::blob_to_kzg_commitment(blob, &kzg_settings);

            if res.is_ok() {
                let expectedCommitment = get_bytes48(test.join("commitment.txt"));
                assert_eq!(res.unwrap().bytes, expectedCommitment.bytes)
            } else {
                assert!(!test.join("commitment.txt").exists());
            }
        }
    }

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_compute_kzg_proof() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let tests = fs::read_dir(COMPUTE_KZG_PROOF_TESTS)
            .unwrap()
            .map(|t| t.unwrap().path());
        for test in tests {
            let blob = get_blob(test.join("blob.txt"));
            let input_point = get_bytes32(test.join("input_point.txt"));
            let res = KZGProof::compute_kzg_proof(blob, input_point, &kzg_settings);

            if res.is_ok() {
                let expected_proof = get_bytes48(test.join("proof.txt"));
                assert_eq!(res.unwrap().bytes, expected_proof.bytes)
            } else {
                assert!(!test.join("proof.txt").exists());
            }
        }
    }

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_compute_blob_kzg_proof() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let tests = fs::read_dir(COMPUTE_BLOB_KZG_PROOF_TESTS)
            .unwrap()
            .map(|t| t.unwrap().path());
        for test in tests {
            let blob = get_blob(test.join("blob.txt"));
            let res = KZGProof::compute_blob_kzg_proof(blob, &kzg_settings);

            if res.is_ok() {
                let expected_proof = get_bytes48(test.join("proof.txt"));
                assert_eq!(res.unwrap().bytes, expected_proof.bytes)
            } else {
                assert!(!test.join("proof.txt").exists());
            }
        }
    }

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_verify_kzg_proof() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let tests = fs::read_dir(VERIFY_KZG_PROOF_TESTS)
            .unwrap()
            .map(|t| t.unwrap().path());
        for test in tests {
            let commitment = get_bytes48(test.join("commitment.txt"));
            let input_point = get_bytes32(test.join("input_point.txt"));
            let claimed_value = get_bytes32(test.join("claimed_value.txt"));
            let proof = get_bytes48(test.join("proof.txt"));
            let res = KZGProof::verify_kzg_proof(
                commitment,
                input_point,
                claimed_value,
                proof,
                &kzg_settings,
            );

            if res.is_ok() {
                let expected_ok = get_boolean(test.join("ok.txt"));
                assert!(expected_ok)
            } else {
                assert!(!test.join("ok.txt").exists());
            }
        }
    }

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_verify_blob_kzg_proof() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let tests = fs::read_dir(VERIFY_BLOB_KZG_PROOF_TESTS)
            .unwrap()
            .map(|t| t.unwrap().path());
        for test in tests {
            let blob = get_blob(test.join("blob.txt"));
            let commitment = get_bytes48(test.join("commitment.txt"));
            let proof = get_bytes48(test.join("proof.txt"));
            let res = KZGProof::verify_blob_kzg_proof(blob, commitment, proof, &kzg_settings);

            if res.is_ok() {
                let expected_ok = get_boolean(test.join("ok.txt"));
                assert!(expected_ok);
            } else {
                assert!(!test.join("ok.txt").exists());
            }
        }
    }

    #[cfg(not(feature = "minimal-spec"))]
    #[test]
    fn test_verify_blob_kzg_proof_batch() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let tests = fs::read_dir(VERIFY_BLOB_KZG_PROOF_BATCH_TESTS)
            .unwrap()
            .map(|t| t.unwrap().path());
        for test in tests {
            let mut blobFiles = fs::read_dir(test.join("blobs"))
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect::<Vec<_>>();
            blobFiles.sort_by_key(|dir| dir.path());
            let blobs = blobFiles
                .iter()
                .map(|blobFile| get_blob(blobFile.path()))
                .collect::<Vec<Blob>>();

            let mut commitmentFiles = fs::read_dir(test.join("commitments"))
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect::<Vec<_>>();
            commitmentFiles.sort_by_key(|dir| dir.path());
            let commitments = commitmentFiles
                .iter()
                .map(|commitmentFile| get_bytes48(commitmentFile.path()))
                .collect::<Vec<Bytes48>>();

            let mut proof_files = fs::read_dir(test.join("proofs"))
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect::<Vec<_>>();
            proof_files.sort_by_key(|dir| dir.path());
            let proofs = proof_files
                .iter()
                .map(|proof_file| get_bytes48(proof_file.path()))
                .collect::<Vec<Bytes48>>();

            let res = KZGProof::verify_blob_kzg_proof_batch(
                blobs.as_slice(),
                commitments.as_slice(),
                proofs.as_slice(),
                &kzg_settings,
            );

            if res.is_ok() {
                let expected_ok = get_boolean(test.join("ok.txt"));
                assert!(expected_ok);
            } else {
                assert!(!test.join("ok.txt").exists());
            }
        }
    }
}
