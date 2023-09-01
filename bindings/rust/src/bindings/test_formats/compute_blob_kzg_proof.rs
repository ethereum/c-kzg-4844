#![allow(dead_code)]

use crate::{Blob, Error, KzgCommitment, KzgProof};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
    commitment: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Result<Blob, Error> {
        Blob::from_hex(self.blob)
    }

    pub fn get_commitment(&self) -> Result<KzgCommitment, Error> {
        KzgCommitment::from_hex(self.commitment)
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
    pub fn get_output(&self) -> Option<KzgProof> {
        self.output.map(|s| KzgProof::from_hex(s).unwrap())
    }
}
