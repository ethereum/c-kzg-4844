#![allow(dead_code)]

use crate::{Blob, Bytes48, Error};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    blobs: Vec<String>,
    commitments: Vec<String>,
    proofs: Vec<String>,
}

impl Input {
    pub fn get_blobs(&self) -> Result<Vec<Box<Blob>>, Error> {
        self.blobs
            .iter()
            .map(|s| s.replace("0x", ""))
            .map(|hex_str| hex::decode(hex_str).unwrap())
            .map(|bytes| Blob::from_bytes(bytes.as_slice()))
            .collect::<Result<Vec<Box<Blob>>, Error>>()
    }

    pub fn get_commitments(&self) -> Result<Vec<Bytes48>, Error> {
        self.commitments
            .iter()
            .map(|s| s.replace("0x", ""))
            .map(|hex_str| hex::decode(hex_str).unwrap())
            .map(|bytes| Bytes48::from_bytes(bytes.as_slice()))
            .collect::<Result<Vec<Bytes48>, Error>>()
    }

    pub fn get_proofs(&self) -> Result<Vec<Bytes48>, Error> {
        self.proofs
            .iter()
            .map(|s| s.replace("0x", ""))
            .map(|hex_str| hex::decode(hex_str).unwrap())
            .map(|bytes| Bytes48::from_bytes(bytes.as_slice()))
            .collect::<Result<Vec<Bytes48>, Error>>()
    }
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    output: Option<bool>,
}

impl Test {
    pub fn get_output(&self) -> Option<bool> {
        self.output
    }
}
