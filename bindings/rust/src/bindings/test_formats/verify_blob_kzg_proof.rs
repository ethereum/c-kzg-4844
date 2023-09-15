#![allow(dead_code)]

use crate::{Blob, Bytes48, Error, KzgSettings};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
    commitment: &'a str,
    proof: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self, s: &KzgSettings) -> Result<Blob, Error> {
        Blob::from_hex(self.blob, s)
    }

    pub fn get_commitment(&self) -> Result<Bytes48, Error> {
        Bytes48::from_hex(self.commitment)
    }

    pub fn get_proof(&self) -> Result<Bytes48, Error> {
        Bytes48::from_hex(self.proof)
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
