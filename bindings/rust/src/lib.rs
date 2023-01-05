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

pub const BYTES_PER_G1_POINT: usize = 48;
pub const BYTES_PER_G2_POINT: usize = 96;

/// Number of G2 points required for the kzg trusted setup.
/// 65 is fixed and is used for providing multiproofs up to 64 field elements.
const NUM_G2_POINTS: usize = 65;

#[derive(Debug)]
pub enum Error {
    /// The KZG proof is invalid.
    InvalidKzgProof(String),
    /// The KZG commitment is invalid.
    InvalidKzgCommitment(String),
    /// The provided trusted setup is invalid.
    InvalidTrustedSetup(String),
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
pub struct BlsFieldElement(bindings::BLSFieldElement);

impl BlsFieldElement {
    pub fn bytes_to_bls_field(
        bytes: [u8; BYTES_PER_FIELD_ELEMENT as usize],
    ) -> Result<Self, Error> {
        let mut bls_field_element = MaybeUninit::<bindings::BLSFieldElement>::uninit();
        unsafe {
            let res = bindings::bytes_to_bls_field(bls_field_element.as_mut_ptr(), bytes.as_ptr());
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(Self(bls_field_element.assume_init()))
            } else {
                Err(Error::CError(res))
            }
        }
    }
}

/// Holds the parameters of a kzg trusted setup ceremony.
pub struct KzgSettings(bindings::KZGSettings);
impl KzgSettings {
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
        let mut kzg_settings = MaybeUninit::<bindings::KZGSettings>::uninit();
        unsafe {
            let n1 = g1_bytes.len();
            let n2 = g2_bytes.len();

            let res = bindings::load_trusted_setup(
                kzg_settings.as_mut_ptr(),
                g1_bytes.as_ptr() as *const u8,
                n1,
                g2_bytes.as_ptr() as *const u8,
                n2,
            );
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(Self(kzg_settings.assume_init()))
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
        let mut kzg_settings = MaybeUninit::<bindings::KZGSettings>::uninit();
        unsafe {
            let file_ptr = fopen(file_path.as_ptr(), &('r' as libc::c_char));
            let res = bindings::load_trusted_setup_file(kzg_settings.as_mut_ptr(), file_ptr);
            if let C_KZG_RET::C_KZG_OK = res {
                Ok(Self(kzg_settings.assume_init()))
            } else {
                Err(Error::InvalidTrustedSetup(format!(
                    "Invalid trusted setup: {:?}",
                    res
                )))
            }
        }
    }
}

impl Drop for KzgSettings {
    fn drop(&mut self) {
        unsafe { bindings::free_trusted_setup(&mut self.0) }
    }
}

pub struct KzgProof(bindings::KZGProof);

impl KzgProof {
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
        Ok(Self(bytes_to_g1(bytes)?))
    }

    pub fn to_bytes(&self) -> [u8; BYTES_PER_G1_POINT] {
        bytes_from_g1(self.0)
    }

    pub fn as_hex_string(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn compute_aggregate_kzg_proof(
        blobs: &[Blob],
        kzg_settings: &KzgSettings,
    ) -> Result<Self, Error> {
        let mut kzg_proof = MaybeUninit::<bindings::KZGProof>::uninit();
        unsafe {
            let res = bindings::compute_aggregate_kzg_proof(
                kzg_proof.as_mut_ptr(),
                blobs.as_ptr() as *const u8,
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
        expected_kzg_commitments: &[KzgCommitment],
        kzg_settings: &KzgSettings,
    ) -> Result<bool, Error> {
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            // TODO: pass without allocating a vec
            let res = bindings::verify_aggregate_kzg_proof(
                verified.as_mut_ptr(),
                blobs.as_ptr() as *const u8,
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
        kzg_commitment: KzgCommitment,
        z: [u8; BYTES_PER_FIELD_ELEMENT],
        y: [u8; BYTES_PER_FIELD_ELEMENT],
        kzg_settings: &KzgSettings,
    ) -> Result<bool, Error> {
        let mut verified: MaybeUninit<bool> = MaybeUninit::uninit();
        unsafe {
            let res = bindings::verify_kzg_proof(
                verified.as_mut_ptr(),
                &kzg_commitment.0,
                z.as_ptr(),
                y.as_ptr(),
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

pub struct KzgCommitment(bindings::KZGCommitment);

impl KzgCommitment {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES_PER_COMMITMENT {
            return Err(Error::InvalidKzgCommitment(format!(
                "Invalid byte length. Expected {} got {}",
                BYTES_PER_PROOF,
                bytes.len(),
            )));
        }
        let mut proof_bytes = [0; BYTES_PER_COMMITMENT];
        proof_bytes.copy_from_slice(bytes);
        Ok(Self(bytes_to_g1(bytes)?))
    }

    pub fn to_bytes(&self) -> [u8; BYTES_PER_G1_POINT] {
        bytes_from_g1(self.0)
    }

    pub fn as_hex_string(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn blob_to_kzg_commitment(mut blob: Blob, kzg_settings: &KzgSettings) -> Self {
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
    use rand::{rngs::ThreadRng, Rng};

    fn generate_random_blob(rng: &mut ThreadRng) -> Blob {
        let mut arr: Blob = [0; BYTES_PER_BLOB];
        rng.fill(&mut arr[..]);
        // Ensure that the blob is canonical by ensuring that
        // each field element contained in the blob is < BLS_MODULUS
        for i in 0..FIELD_ELEMENTS_PER_BLOB {
            arr[i * BYTES_PER_FIELD_ELEMENT + BYTES_PER_FIELD_ELEMENT - 1] = 0;
        }
        arr
    }

    fn test_simple(trusted_setup_file: PathBuf) {
        let mut rng = rand::thread_rng();
        assert!(trusted_setup_file.exists());
        let kzg_settings = KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let num_blobs: usize = rng.gen_range(0..16);
        let mut blobs: Vec<Blob> = (0..num_blobs)
            .map(|_| generate_random_blob(&mut rng))
            .collect();

        let kzg_commitments: Vec<KzgCommitment> = blobs
            .clone()
            .into_iter()
            .map(|blob| KzgCommitment::blob_to_kzg_commitment(blob, &kzg_settings))
            .collect();

        let kzg_proof = KzgProof::compute_aggregate_kzg_proof(&blobs, &kzg_settings).unwrap();

        assert!(kzg_proof
            .verify_aggregate_kzg_proof(&blobs, &kzg_commitments, &kzg_settings)
            .unwrap());

        let incorrect_blob = generate_random_blob(&mut rng);
        blobs.pop();
        blobs.push(incorrect_blob);

        assert!(!kzg_proof
            .verify_aggregate_kzg_proof(&blobs, &kzg_commitments, &kzg_settings)
            .unwrap());
    }

    #[test]
    fn test_end_to_end() {
        let trusted_setup_file;
        if cfg!(feature = "minimal-spec") {
            trusted_setup_file = PathBuf::from("../../src/trusted_setup_4.txt");
        } else {
            trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        }
        test_simple(trusted_setup_file);
    }

    #[test]
    fn test_compute_agg_proof() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let test_file = PathBuf::from("test_vectors/public_agg_proof.json");
        let json_data: serde_json::Value =
            serde_json::from_reader(std::fs::File::open(test_file).unwrap()).unwrap();

        let tests = json_data.get("TestCases").unwrap().as_array().unwrap();
        for test in tests.iter() {
            let expected_proof = test.get("Proof").unwrap().as_str().unwrap();

            let expected_kzg_commitments = test
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
                    blob_data
                })
                .collect::<Vec<_>>();

            let proof = KzgProof::compute_aggregate_kzg_proof(&blobs, &kzg_settings).unwrap();
            assert_eq!(proof.as_hex_string(), expected_proof);

            for (i, blob) in blobs.into_iter().enumerate() {
                let commitment = KzgCommitment::blob_to_kzg_commitment(blob, &kzg_settings);
                assert_eq!(
                    commitment.as_hex_string().as_str(),
                    expected_kzg_commitments[i]
                );
            }
        }
    }

    #[test]
    fn test_verify_kzg_proof() {
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        let test_file = PathBuf::from("test_vectors/public_verify_kzg_proof.json");
        let json_data: serde_json::Value =
            serde_json::from_reader(std::fs::File::open(test_file).unwrap()).unwrap();

        let tests = json_data.get("TestCases").unwrap().as_array().unwrap();
        for test in tests.iter() {
            let proof = test.get("Proof").unwrap().as_str().unwrap();
            let kzg_proof = KzgProof::from_bytes(&hex::decode(proof).unwrap()).unwrap();

            let commitment = test.get("Commitment").unwrap().as_str().unwrap();
            let kzg_commitment =
                KzgCommitment::from_bytes(&hex::decode(commitment).unwrap()).unwrap();

            let z = test.get("InputPoint").unwrap().as_str().unwrap();
            let mut z_bytes = [0; BYTES_PER_FIELD_ELEMENT];
            z_bytes.copy_from_slice(&hex::decode(z).unwrap());

            let y = test.get("ClaimedValue").unwrap().as_str().unwrap();
            let mut y_bytes = [0; BYTES_PER_FIELD_ELEMENT];
            y_bytes.copy_from_slice(&hex::decode(y).unwrap());

            assert!(kzg_proof
                .verify_kzg_proof(kzg_commitment, z_bytes, y_bytes, &kzg_settings)
                .unwrap());
        }
    }
}
