#![allow(dead_code)]

use crate::{Blob, Bytes48, Error};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
    commitment: &'a str,
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
}

#[derive(Deserialize)]
pub struct Test<'a> {
    #[serde(borrow)]
    pub input: Input<'a>,
    #[serde(borrow)]
    output: Option<&'a str>,
}

impl Test<'_> {
    pub fn get_output(&self) -> Option<Bytes48> {
        self.output
            .map(|s| s.replace("0x", ""))
            .map(|hex_str| hex::decode(hex_str).unwrap())
            .map(|bytes| Bytes48::from_bytes(&bytes).unwrap())
    }
}
