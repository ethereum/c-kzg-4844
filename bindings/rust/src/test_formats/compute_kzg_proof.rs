#![allow(dead_code)]

use crate::{Blob, Bytes32, Bytes48, Error};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
    z: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Result<Blob, Error> {
        let hex_str = self.blob.replace("0x", "");
        let bytes = hex::decode(hex_str).unwrap();
        Blob::from_bytes(&bytes)
    }

    pub fn get_z(&self) -> Result<Bytes32, Error> {
        let hex_str = self.z.replace("0x", "");
        let bytes = hex::decode(hex_str).unwrap();
        Bytes32::from_bytes(&bytes)
    }
}

#[derive(Deserialize)]
pub struct Test<'a> {
    #[serde(borrow)]
    pub input: Input<'a>,
    #[serde(borrow)]
    output: Option<(&'a str, &'a str)>,
}

impl Test<'_> {
    pub fn get_output(&self) -> Option<(Bytes48, Bytes32)> {
        if self.output.is_none() {
            return None;
        }

        let proof_hex = self.output.as_ref().unwrap().0
            .replace("0x", "");
        let proof_bytes = hex::decode(proof_hex).unwrap();
        let proof = Bytes48::from_bytes(&proof_bytes).unwrap();

        let z_hex = self.output.as_ref().unwrap().1
            .replace("0x", "");
        let z_bytes = hex::decode(z_hex).unwrap();
        let z = Bytes32::from_bytes(&z_bytes).unwrap();

        Some((proof, z))
    }
}
