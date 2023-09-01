#![allow(dead_code)]

use crate::{Blob, Error, KzgCommitment, KzgProof};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
    commitment: &'a str,
    proof: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Result<Blob, Error> {
        Blob::from_hex(self.blob)
    }

    pub fn get_commitment(&self) -> Result<KzgCommitment, Error> {
        KzgCommitment::from_hex(self.commitment)
    }

    pub fn get_proof(&self) -> Result<KzgProof, Error> {
        KzgProof::from_hex(self.proof)
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
