pub mod blob_to_kzg_commitment_test;
pub mod compute_blob_kzg_proof;
pub mod compute_kzg_proof;
pub mod verify_blob_kzg_proof;
pub mod verify_blob_kzg_proof_batch;
pub mod verify_kzg_proof;

use bytes::Bytes;
use crate::Error;

use super::hex_to_bytes;

pub(crate) fn deserialize_blob(blob_str: &str) -> Result<Bytes, Error> {
    let bytes = hex_to_bytes(blob_str)?;
    Ok(Bytes::from(bytes))
}