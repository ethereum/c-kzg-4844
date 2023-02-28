#![allow(dead_code)]

use crate::Blob;
use crate::Bytes48;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
    commitment: &'a str,
    proof: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Blob {
        Blob::from_bytes(&hex::decode(self.blob.replace("0x", "")).unwrap()).unwrap()
    }

    pub fn get_commitment(&self) -> Bytes48 {
        Bytes48::from_bytes(&hex::decode(self.commitment.replace("0x", "")).unwrap()).unwrap()
    }

    pub fn get_proof(&self) -> Bytes48 {
        Bytes48::from_bytes(&hex::decode(self.proof.replace("0x", "")).unwrap()).unwrap()
    }
}

#[derive(Deserialize)]
pub struct Test<'a> {
    #[serde(borrow)]
    pub input: Input<'a>,
    output: Option<bool>,
}

impl Test<'_> {
    pub fn get_output(&self) -> Option<bool> {
        self.output
    }
}
