//! Serde serialization and deserialization for the basic types in this crate.
use crate::{Blob, Bytes48};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serialize a byte vec as a hex string with 0x prefix
pub fn serialize_bytes<S, T>(x: T, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    s.serialize_str(&format!("0x{}", hex::encode(x.as_ref())))
}

impl Serialize for Blob {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_bytes(self.bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes_res = match value.strip_prefix("0x") {
            Some(value) => hex::decode(value),
            None => hex::decode(&value),
        };

        let bytes = bytes_res.map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Blob::from_bytes(bytes.as_slice()).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    }
}

impl Serialize for Bytes48 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_bytes(self.bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for Bytes48 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes_res = match value.strip_prefix("0x") {
            Some(value) => hex::decode(value),
            None => hex::decode(&value),
        };

        let bytes = bytes_res.map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Bytes48::from_bytes(bytes.as_slice())
            .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use rand::{rngs::ThreadRng, Rng};
    use std::path::PathBuf;

    fn generate_random_blob(rng: &mut ThreadRng) -> Blob {
        let mut arr = [0u8; BYTES_PER_BLOB];
        rng.fill(&mut arr[..]);
        // Ensure that the blob is canonical by ensuring that
        // each field element contained in the blob is < BLS_MODULUS
        for i in 0..FIELD_ELEMENTS_PER_BLOB {
            arr[i * BYTES_PER_FIELD_ELEMENT] = 0;
        }
        arr.into()
    }

    #[test]
    fn test_serialize_roundtrip() {
        // load setup so we can create commitments and blobs
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        // generate blob, commitment, proof
        let mut rng = rand::thread_rng();
        let blob = generate_random_blob(&mut rng);
        let commitment =
            KZGCommitment::blob_to_kzg_commitment(blob.clone(), &kzg_settings).unwrap();
        let proof =
            KZGProof::compute_blob_kzg_proof(blob.clone(), commitment.to_bytes(), &kzg_settings)
                .unwrap();

        // check blob serialization
        let blob_serialized = serde_json::to_string(&blob).unwrap();
        let blob_deserialized: Blob = serde_json::from_str(&blob_serialized).unwrap();
        assert_eq!(blob, blob_deserialized);

        // check commitment serialization
        let commitment_serialized = serde_json::to_string(&commitment.to_bytes()).unwrap();
        let commitment_deserialized: Bytes48 =
            serde_json::from_str(&commitment_serialized).unwrap();
        assert_eq!(commitment.to_bytes(), commitment_deserialized);

        // check proof serialization
        let proof_serialized = serde_json::to_string(&proof.to_bytes()).unwrap();
        let proof_deserialized: Bytes48 = serde_json::from_str(&proof_serialized).unwrap();
        assert_eq!(proof.to_bytes(), proof_deserialized);
    }

    #[test]
    fn test_serialize_blob_with_prefix() {
        // generate blob
        let mut rng = rand::thread_rng();
        let blob = generate_random_blob(&mut rng);

        // check blob serialization
        let blob_serialized = serde_json::to_string(&blob).unwrap();

        // check that this begins with a quote and 0x
        let mut chars = blob_serialized.chars();
        assert_eq!(chars.next().unwrap(), '"');
        assert_eq!(chars.next().unwrap(), '0');
        assert_eq!(chars.next().unwrap(), 'x');

        // check that it ends with a quote (sanity check)
        assert_eq!(chars.last().unwrap(), '"');
    }

    #[test]
    fn test_serialize_bytes_48_with_prefix() {
        // load setup so we can create a commitments
        let trusted_setup_file = PathBuf::from("../../src/trusted_setup.txt");
        assert!(trusted_setup_file.exists());
        let kzg_settings = KZGSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

        // generate blob just to calculate a commitment
        let mut rng = rand::thread_rng();
        let blob = generate_random_blob(&mut rng);
        let commitment =
            KZGCommitment::blob_to_kzg_commitment(blob.clone(), &kzg_settings).unwrap();

        // check blob serialization
        let blob_serialized = serde_json::to_string(&commitment.to_bytes()).unwrap();

        // check that this begins with a quote and 0x
        let mut chars = blob_serialized.chars();
        assert_eq!(chars.next().unwrap(), '"');
        assert_eq!(chars.next().unwrap(), '0');
        assert_eq!(chars.next().unwrap(), 'x');

        // check that it ends with a quote (sanity check)
        assert_eq!(chars.last().unwrap(), '"');
    }
}
