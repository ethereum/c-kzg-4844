#![allow(dead_code)]

use crate::{Bytes32, Error, KzgCommitment, KzgProof};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    commitment: &'a str,
    z: &'a str,
    y: &'a str,
    proof: &'a str,
}

impl Input<'_> {
    pub fn get_commitment(&self) -> Result<KzgCommitment, Error> {
        KzgCommitment::from_hex(self.commitment)
    }

    pub fn get_z(&self) -> Result<Bytes32, Error> {
        Bytes32::from_hex(self.z)
    }

    pub fn get_y(&self) -> Result<Bytes32, Error> {
        Bytes32::from_hex(self.y)
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
