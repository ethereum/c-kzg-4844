#![allow(dead_code)]

use crate::{Blob, Bytes48, Error};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
    commitment: &'a str,
    proof: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Result<Blob, Error> {
        let hex_str = self.blob.replace("0x", "");
        let bytes = hex::decode(hex_str).unwrap();
        Blob::from_bytes(&bytes)
    }

    pub fn get_commitment(&self) -> Result<Bytes48, Error> {
        let hex_str = self.commitment.replace("0x", "");
        let bytes = hex::decode(hex_str).unwrap();
        Bytes48::from_bytes(&bytes)
    }

    pub fn get_proof(&self) -> Result<Bytes48, Error> {
        let hex_str = self.proof.replace("0x", "");
        let bytes = hex::decode(hex_str).unwrap();
        Bytes48::from_bytes(&bytes)
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
