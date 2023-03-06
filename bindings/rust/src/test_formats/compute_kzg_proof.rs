#![allow(dead_code)]

use crate::{Blob, Bytes32, Bytes48, Error};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
    z: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Result<Box<Blob>, Error> {
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
